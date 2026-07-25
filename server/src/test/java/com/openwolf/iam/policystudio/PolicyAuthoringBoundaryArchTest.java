package com.openwolf.iam.policystudio;

import com.tngtech.archunit.core.domain.JavaClasses;
import com.tngtech.archunit.core.importer.ClassFileImporter;
import com.tngtech.archunit.core.importer.ImportOption;
import com.tngtech.archunit.lang.ArchRule;
import org.junit.jupiter.api.Test;

import static com.tngtech.archunit.lang.syntax.ArchRuleDefinition.classes;
import static com.tngtech.archunit.lang.syntax.ArchRuleDefinition.noClasses;

/**
 * C2.5 — the LLM is structurally ABSENT from live enforcement. The policy-authoring model client
 * and the policy-studio generation services are an authoring-plane island: no runtime-enforcement
 * code may depend on them.
 *
 * <p>Two layers of proof:
 * <ol>
 *   <li><b>Module boundary (strongest):</b> the gateway — which holds the request path, the Cerbos
 *       entitlement adapter, token verification at every hop, coverage enforcement, and agent
 *       invocation — is a SEPARATE Maven module with no dependency on iam-service, so it cannot
 *       even reference {@link PolicyAuthoringModelClient}. Nothing to assert; it is unbuildable
 *       otherwise.</li>
 *   <li><b>Intra-module (this test):</b> within iam-service, token verification ({@code ..auth..})
 *       and every non-authoring package must not depend on the authoring plane.</li>
 * </ol>
 */
class PolicyAuthoringBoundaryArchTest {

    private static final String STUDIO = "com.openwolf.iam.policystudio";

    private static final JavaClasses IAM = new ClassFileImporter()
            .withImportOption(ImportOption.Predefined.DO_NOT_INCLUDE_TESTS)
            .importPackages("com.openwolf.iam");

    /** The enforcement surfaces that exist inside iam-service. Token verification lives in
     *  {@code ..auth..}; the runtime entitlement/coverage/invocation surfaces live in the gateway
     *  module, which cannot see this package at all (see class javadoc). */
    private static final String[] ENFORCEMENT_PACKAGES = {
            "..auth..",
    };

    @Test
    void llmClientCannotReachEnforcementPackages() {
        // (1) Token verification / auth must not reach the authoring plane.
        ArchRule authIsolated = noClasses()
                .that().resideInAnyPackage(ENFORCEMENT_PACKAGES)
                .should().dependOnClassesThat().resideInAPackage(STUDIO + "..")
                .as("enforcement packages must not depend on the policy-studio authoring plane");
        authIsolated.check(IAM);

        // (2) The model client interface is reachable ONLY from within the authoring plane —
        // nothing outside com.openwolf.iam.policystudio may depend on it.
        ArchRule clientConfined = noClasses()
                .that().resideOutsideOfPackage(STUDIO + "..")
                .should().dependOnClassesThat().areAssignableTo(PolicyAuthoringModelClient.class)
                .as("PolicyAuthoringModelClient must never be injected outside the authoring plane");
        clientConfined.check(IAM);

        // (3) The generation service itself is authoring-plane confined.
        ArchRule serviceConfined = noClasses()
                .that().resideOutsideOfPackage(STUDIO + "..")
                .should().dependOnClassesThat().areAssignableTo(PolicyStudioGenerationService.class)
                .as("the policy-studio generation service must never be reachable from enforcement code");
        serviceConfined.check(IAM);

        // (4) Every implementation of the model client lives in the authoring plane.
        ArchRule implsInStudio = classes()
                .that().areAssignableTo(PolicyAuthoringModelClient.class)
                .should().resideInAPackage(STUDIO + "..")
                .as("all PolicyAuthoringModelClient implementations must live in the authoring plane");
        implsInStudio.check(IAM);

        // (5) C4 — the consequence-diff LLM PROSE seam is authoring-plane only. It phrases an already
        // PDP-computed delta into display text; it must never be reachable from enforcement, exactly
        // like the C2 authoring client. (Same fencing style, extended to the new seam.)
        ArchRule proseClientConfined = noClasses()
                .that().resideOutsideOfPackage(STUDIO + "..")
                .should().dependOnClassesThat().areAssignableTo(ConsequenceProseModelClient.class)
                .as("ConsequenceProseModelClient must never be injected outside the authoring plane");
        proseClientConfined.check(IAM);

        ArchRule proseImplsInStudio = classes()
                .that().areAssignableTo(ConsequenceProseModelClient.class)
                .should().resideInAPackage(STUDIO + "..")
                .as("all ConsequenceProseModelClient implementations must live in the authoring plane");
        proseImplsInStudio.check(IAM);

        // (6) C4 — the consequence-diff service itself is authoring-plane confined.
        ArchRule diffServiceConfined = noClasses()
                .that().resideOutsideOfPackage(STUDIO + "..")
                .should().dependOnClassesThat().areAssignableTo(ConsequenceDiffService.class)
                .as("the consequence-diff service must never be reachable from enforcement code");
        diffServiceConfined.check(IAM);

        // (7) C5 — the policy-lifecycle promotion machine is authoring-plane only. It stages/compiles/
        // probes and compare-and-sets the live pointer; no runtime-enforcement code may reach it.
        ArchRule promotionConfined = noClasses()
                .that().resideOutsideOfPackage(STUDIO + "..")
                .should().dependOnClassesThat()
                .areAssignableTo(com.openwolf.iam.policystudio.lifecycle.PolicyPromotionService.class)
                .as("the policy-promotion service must never be reachable from enforcement code");
        promotionConfined.check(IAM);

        // (8) C5 — the examiner chain service is authoring-plane only (audit reconstruction, not enforcement).
        ArchRule examinerConfined = noClasses()
                .that().resideOutsideOfPackage(STUDIO + "..")
                .should().dependOnClassesThat()
                .areAssignableTo(com.openwolf.iam.policystudio.lifecycle.ExaminerChainService.class)
                .as("the examiner chain service must never be reachable from enforcement code");
        examinerConfined.check(IAM);
    }
}
