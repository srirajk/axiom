package com.openwolf.iam.policystudio;

import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;

/**
 * The in-process, fully-reproducible PDP source (Axiom Story C4): it evaluates each cell through the
 * C3 {@link PolicyExpectationEvaluator}, which reasons over the same closed decision set the runtime
 * Cerbos PDP emits for the generated tenant-restriction shape. No Docker, no network — so the harness
 * pins the diff behaviour byte-for-byte on any JDK 25 box (the same reproducibility rationale C3 uses
 * for its catch-rate: constrained fidelity evaluator for the deterministic number, real Cerbos
 * ({@link CerbosBatchDecisionSource}) for belt-and-braces evidence).
 *
 * <p>Ground truth here is a POLICY DECISION, never an LLM output — which is the property C4.1 proves.
 */
@Component
public class LocalPdpDecisionSource implements PdpDecisionSource {

    static final String SOURCE_ID = "local-pdp-fidelity-evaluator";

    private final PolicyExpectationEvaluator evaluator;

    public LocalPdpDecisionSource(PolicyExpectationEvaluator evaluator) {
        this.evaluator = evaluator;
    }

    @Override
    public String sourceId() {
        return SOURCE_ID;
    }

    @Override
    public boolean isAvailable() {
        return true; // pure in-process — always available
    }

    @Override
    public PdpBatchResult evaluate(BundleSnapshot bundle, List<FixtureCell> cells) {
        if (bundle.policy() == null) {
            throw new IllegalArgumentException(
                    "the in-process fidelity source requires an explicit tenant restriction child; "
                            + "a base-only bundle must be evaluated by the real-Cerbos source");
        }
        List<PdpDecision> decisions = new ArrayList<>(cells.size());
        for (FixtureCell cell : cells) {
            Effect effect = decide(bundle, cell);
            String callId = SOURCE_ID + "/" + bundle.bundleId() + "/" + cell.label();
            String raw = "{\"source\":\"" + SOURCE_ID + "\",\"bundleId\":\"" + bundle.bundleId()
                    + "\",\"cell\":\"" + cell.label() + "\",\"effect\":\"EFFECT_" + effect + "\"}";
            decisions.add(new PdpDecision(cell.label(), effect, callId, raw));
        }
        return new PdpBatchResult(bundle.bundleId(), SOURCE_ID, decisions);
    }

    private Effect decide(BundleSnapshot bundle, FixtureCell cell) {
        // Adapt a decision cell to the C3 expectation shape: the expected effect is a placeholder the
        // evaluator ignores; the probe kind must reflect cross-tenant homing so the inherited
        // tenant-equality backstop is applied exactly as the runtime PDP would.
        Expectation probe = new Expectation(
                cell.principalRoles(),
                cell.principalTenant(),
                cell.resourceTenant(),
                cell.resourceAttrs(),
                cell.action(),
                Effect.ALLOW, // placeholder — evaluate() returns the actual decision, never compares to this
                cell.isCrossTenant() ? ProbeKind.CROSS_TENANT : ProbeKind.POSITIVE,
                cell.label());
        try {
            return evaluator.evaluate(bundle.policy(), bundle.ceiling(), probe);
        } catch (PolicyExpectationEvaluator.IndeterminateException indeterminate) {
            // The constrained evaluator refuses to guess. A consequence diff must not fabricate a
            // truth value — surface it rather than silently pick an effect.
            throw new IllegalStateException(
                    "consequence cell '" + cell.label() + "' is not decidable by the in-process "
                            + "fidelity evaluator; evaluate this bundle with the real-Cerbos source", indeterminate);
        }
    }
}
