package com.openwolf.iam.policystudio;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.stereotype.Service;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

/**
 * The C3 draft gate — independent test-scenario generation and the fix to the oracle problem (Axiom
 * Story C3, "the moat").
 *
 * <p>Pipeline for one draft:
 * <pre>
 *   authoring request (intent + vocab + scope + ceiling)
 *        │  TestScenarioRequest.fromAuthoring — a lossy projection that DROPS the proposal/IR/YAML
 *        ▼
 *   independent oracle proposes EXPECTED decisions from the intent alone   TestScenarioModelClient
 *        │  (structurally cannot see the candidate — TestScenarioRequest has no YAML field)
 *        ▼
 *   mechanically inject negative probes: cross-tenant / wrong-segment / missing-attribute (all DENY)
 *        │  NegativeProbeInjector  (3 probes per intent-implied ALLOW)
 *        ▼
 *   run the oracle + probes against the candidate       PolicyExpectationEvaluator
 *   run C2's deterministic gate against the candidate    GeneratedPolicyValidator
 *   compile candidate + base bundle (runs the hand-owned B3 invariant suite)   CerbosCompileGate
 *        ▼
 *   CAUGHT if ANY layer flags it; the report records WHERE (and whether ONLY the oracle did).
 * </pre>
 *
 * <p>The independent oracle is generated in a context that never sees the candidate YAML, so a wrong
 * policy cannot manufacture self-consistent green tests. That is what a co-generated (policy+tests in
 * one prompt) approach cannot guarantee.
 *
 * <p><b>Boundary:</b> authoring-plane only; ArchUnit ({@code TestGenIsolationArchTest},
 * {@code PolicyAuthoringBoundaryArchTest}) proves no runtime-enforcement code can reach this service.
 */
@Service
@ConditionalOnBean(TestScenarioModelClient.class)
public class IndependentTestGenService {

    private static final Logger log = LoggerFactory.getLogger(IndependentTestGenService.class);

    private final TestScenarioModelClient oracle;
    private final NegativeProbeInjector probeInjector;
    private final PolicyExpectationEvaluator evaluator;
    private final GeneratedPolicyValidator validator;
    private final CanonicalPolicyWriter writer;
    private final CerbosCompileGate compileGate;
    private final String baseBundleDir;

    public IndependentTestGenService(
            TestScenarioModelClient oracle,
            NegativeProbeInjector probeInjector,
            PolicyExpectationEvaluator evaluator,
            GeneratedPolicyValidator validator,
            CanonicalPolicyWriter writer,
            CerbosCompileGate compileGate,
            @Value("${iam.policy-studio.base-bundle-dir:/app/platform-policy/policies}") String baseBundleDir) {
        this.oracle = oracle;
        this.probeInjector = probeInjector;
        this.evaluator = evaluator;
        this.validator = validator;
        this.writer = writer;
        this.compileGate = compileGate;
        this.baseBundleDir = baseBundleDir;
    }

    /**
     * Generate the independent oracle for a request and expand it with negative probes — WITHOUT ever
     * touching a candidate. This is the isolated generation half of the moat.
     */
    public TestExpectationSet generateOracle(PolicyAuthoringRequest authoring, ProbeAttributes probeAttrs) {
        TestScenarioRequest oracleReq = TestScenarioRequest.fromAuthoring(authoring);
        TestExpectationSet positives = oracle.proposeExpectations(oracleReq);
        return probeInjector.inject(positives, probeAttrs, authoring.vocabulary());
    }

    /**
     * Assess a candidate draft against its independently-generated oracle + the deterministic gate +
     * (when available) the pinned-Cerbos compile that runs the hand-owned invariant suite.
     *
     * @param runCompile when true and Docker/cerbos is available, also compile against the base bundle
     *                   (which embeds the B3 invariants) — the belt-and-braces layer. When false or
     *                   unavailable the in-process validator + oracle layers still decide the outcome
     *                   (fully reproducible).
     */
    public TestGenReport assess(PolicyAuthoringRequest authoring, PolicyIR candidate,
                                ProbeAttributes probeAttrs, boolean runCompile) {
        TestExpectationSet oracleSet = generateOracle(authoring, probeAttrs);

        // Layer: independent oracle + injected probes ────────────────────────────────────────────
        List<Expectation> oracleFailures = new ArrayList<>();
        int indeterminate = 0;
        for (Expectation e : oracleSet.expectations()) {
            try {
                Effect actual = evaluator.evaluate(candidate, authoring.baseCeiling(), e);
                if (actual != e.expected()) {
                    oracleFailures.add(e);
                }
            } catch (PolicyExpectationEvaluator.IndeterminateException indet) {
                indeterminate++;
            }
        }

        // Layer: C2 deterministic gate ────────────────────────────────────────────────────────────
        GeneratedPolicyValidator.Result vr = validator.validate(candidate, authoring);

        // Layer: pinned-Cerbos compile (runs the hand-owned B3 invariant suite embedded in the bundle)
        boolean invariantSuiteRun = false;
        boolean compileCaught = false;
        String compileOutput = "compile layer not requested";
        if (runCompile && compileGate.isAvailable()) {
            String canonical = writer.write(candidate);
            String candidateFile = "generated_" + candidate.resource() + "_"
                    + safe(candidate.scope()) + ".yaml";
            CerbosCompileGate.CompileOutcome outcome =
                    compileGate.compile(canonical, Path.of(baseBundleDir), candidateFile);
            invariantSuiteRun = true;
            compileCaught = !outcome.success();
            compileOutput = outcome.output();
        }

        boolean caught = !vr.accepted() || !oracleFailures.isEmpty() || compileCaught;
        // The C2 deterministic gate is credited first (it is the cheaper, structural layer); the
        // ORACLE layer is credited only when the deterministic gate ACCEPTED the candidate — which is
        // exactly the moat-critical case: a validator-clean policy the co-generated tests would have
        // passed, caught solely because the oracle was built from intent, not from the policy.
        CatchLayer primary;
        if (!vr.accepted()) {
            primary = CatchLayer.VALIDATOR;
        } else if (!oracleFailures.isEmpty()) {
            primary = CatchLayer.ORACLE;
        } else if (compileCaught) {
            primary = CatchLayer.COMPILE;
        } else {
            primary = CatchLayer.UNCAUGHT;
        }
        boolean moatCritical = vr.accepted() && !oracleFailures.isEmpty();

        log.debug("C3 draft gate: caught={} layer={} oracleFailures={} indeterminate={} invariantRun={}",
                caught, primary, oracleFailures.size(), indeterminate, invariantSuiteRun);

        return new TestGenReport(caught, primary, moatCritical, !vr.accepted(), vr.violations(),
                oracleFailures, indeterminate, invariantSuiteRun, compileCaught, compileOutput,
                oracleSet.renderTestYaml(candidate.resource()));
    }

    private static String safe(String scope) {
        return scope == null ? "root" : scope.replace('.', '_');
    }

    /**
     * The outcome of one C3 draft assessment.
     *
     * @param caught            whether any layer flagged the candidate
     * @param primaryLayer      the layer credited (ORACLE first, to surface the moat)
     * @param moatCritical      true iff ONLY the independent oracle caught it — a co-generated suite
     *                          would have passed
     * @param validatorRejected whether C2's deterministic gate rejected
     * @param validatorViolations the deterministic-gate violations (empty if it accepted)
     * @param oracleFailures    the expectations the candidate got wrong (intent-implied vs actual)
     * @param indeterminate     expectations whose decision was outside the evaluator's supported subset
     * @param invariantSuiteRun whether the pinned-Cerbos compile (with the B3 invariants) actually ran
     * @param compileCaught     whether that compile flagged the candidate
     * @param compileOutput     compile output (diagnostic)
     * @param oracleTestYaml    the rendered {@code _test.yaml} of the independent oracle (checked in)
     */
    public record TestGenReport(
            boolean caught,
            CatchLayer primaryLayer,
            boolean moatCritical,
            boolean validatorRejected,
            List<String> validatorViolations,
            List<Expectation> oracleFailures,
            int indeterminate,
            boolean invariantSuiteRun,
            boolean compileCaught,
            String compileOutput,
            String oracleTestYaml) {

        public TestGenReport {
            validatorViolations = List.copyOf(validatorViolations);
            oracleFailures = List.copyOf(oracleFailures);
        }
    }
}
