package com.openwolf.iam.policystudio;

import com.tngtech.archunit.core.domain.JavaClasses;
import com.tngtech.archunit.core.importer.ClassFileImporter;
import com.tngtech.archunit.core.importer.ImportOption;
import com.tngtech.archunit.lang.ArchRule;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Method;
import java.lang.reflect.RecordComponent;
import java.util.Set;

import static com.tngtech.archunit.lang.syntax.ArchRuleDefinition.noClasses;
import static org.assertj.core.api.Assertions.assertThat;

/**
 * C3.1 — the independent test oracle STRUCTURALLY never sees the candidate YAML (the moat).
 *
 * <p>The proof is at the type level: the oracle's only input is {@link TestScenarioRequest}, and the
 * only seam to the oracle is {@link TestScenarioModelClient#proposeExpectations(TestScenarioRequest)}.
 * If either grows a field or parameter of a policy-artifact type — {@link PolicyIR},
 * {@link StudioGenerationResult}, or the {@link CanonicalPolicyWriter}/{@link PolicyYamlParser} that
 * materialise/lower candidate YAML — this test turns red. That is the tripwire against "wiring the
 * generated YAML in to improve the tests", which would collapse the moat back into the oracle problem.
 *
 * <p>Note the asymmetry that makes the moat real: the RUN phase ({@link IndependentTestGenService} /
 * {@link PolicyExpectationEvaluator}) obviously must see the candidate to evaluate it — you run tests
 * against the thing. What must never happen is the GENERATION context seeing it. So the fence is on
 * {@code TestScenarioRequest} + {@code TestScenarioModelClient}, precisely.
 */
class TestGenIsolationArchTest {

    /** Policy-artifact types that would leak the candidate into the oracle's generation context. */
    private static final Set<Class<?>> FORBIDDEN_IN_ORACLE_INPUT = Set.of(
            PolicyIR.class,
            StudioGenerationResult.class,
            CanonicalPolicyWriter.class,
            PolicyYamlParser.class);

    /** The exact, closed set of grounding facts the oracle input may carry (a strict pre-generation subset). */
    private static final Set<Class<?>> ALLOWED_REQUEST_COMPONENTS = Set.of(
            String.class,
            ManifestVocabulary.class,
            TenantScope.class,
            BaseCeiling.class);

    private static final JavaClasses IAM = new ClassFileImporter()
            .withImportOption(ImportOption.Predefined.DO_NOT_INCLUDE_TESTS)
            .importPackages("com.openwolf.iam");

    @Test
    void testGenNeverReceivesYaml() {
        // (1) The oracle input record carries ONLY pre-generation grounding facts — no policy artifact.
        RecordComponent[] components = TestScenarioRequest.class.getRecordComponents();
        assertThat(components)
                .as("TestScenarioRequest must be a record of grounding facts")
                .isNotEmpty();
        for (RecordComponent c : components) {
            assertThat(FORBIDDEN_IN_ORACLE_INPUT)
                    .as("oracle input component '%s' must not be a policy-artifact type", c.getName())
                    .doesNotContain(c.getType());
            assertThat(ALLOWED_REQUEST_COMPONENTS)
                    .as("oracle input component '%s' of type %s is outside the sanctioned grounding-fact set",
                            c.getName(), c.getType().getSimpleName())
                    .contains(c.getType());
            assertThat(c.getName().toLowerCase())
                    .as("oracle input component '%s' must not name a candidate/yaml field", c.getName())
                    .doesNotContain("yaml")
                    .doesNotContain("candidate");
        }

        // (2) The oracle seam accepts ONLY the request — no method parameter is a policy artifact.
        boolean seamPresent = false;
        for (Method m : TestScenarioModelClient.class.getMethods()) {
            for (Class<?> param : m.getParameterTypes()) {
                assertThat(FORBIDDEN_IN_ORACLE_INPUT)
                        .as("oracle client method '%s' parameter %s must not be a policy artifact",
                                m.getName(), param.getSimpleName())
                        .doesNotContain(param);
                if (param.equals(TestScenarioRequest.class)) {
                    seamPresent = true;
                }
            }
        }
        assertThat(seamPresent)
                .as("the oracle seam must accept the isolated TestScenarioRequest")
                .isTrue();

        // (3) Belt-and-braces at the bytecode level: neither the oracle input nor the seam may
        //     depend on the candidate-lowering / materialising / IR types.
        for (Class<?> forbidden : FORBIDDEN_IN_ORACLE_INPUT) {
            ArchRule rule = noClasses()
                    .that().haveFullyQualifiedName(TestScenarioRequest.class.getName())
                    .or().haveFullyQualifiedName(TestScenarioModelClient.class.getName())
                    .should().dependOnClassesThat().haveFullyQualifiedName(forbidden.getName())
                    .as("the oracle generation surface must not depend on " + forbidden.getSimpleName());
            rule.check(IAM);
        }
    }

    @Test
    void oracleGenerationSurfaceIsAuthoringPlaneOnly() {
        // Mirror C2's boundary style: the test-gen seam and service are authoring-plane; runtime token
        // verification (..auth..) must not depend on them.
        ArchRule authIsolated = noClasses()
                .that().resideInAPackage("..auth..")
                .should().dependOnClassesThat().resideInAPackage("com.openwolf.iam.policystudio..")
                .as("enforcement (auth) must not depend on the policy-studio authoring plane (incl. test-gen)");
        authIsolated.check(IAM);

        ArchRule clientConfined = noClasses()
                .that().resideOutsideOfPackage("com.openwolf.iam.policystudio..")
                .should().dependOnClassesThat().areAssignableTo(TestScenarioModelClient.class)
                .as("TestScenarioModelClient must never be injected outside the authoring plane");
        clientConfined.check(IAM);

        ArchRule serviceConfined = noClasses()
                .that().resideOutsideOfPackage("com.openwolf.iam.policystudio..")
                .should().dependOnClassesThat().areAssignableTo(IndependentTestGenService.class)
                .as("the independent test-gen service must never be reachable from enforcement code");
        serviceConfined.check(IAM);
    }
}
