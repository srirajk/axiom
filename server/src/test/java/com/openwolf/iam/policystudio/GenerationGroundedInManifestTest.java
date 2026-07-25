package com.openwolf.iam.policystudio;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * C2.3 — a generated policy references ONLY manifest-declared entity vocabulary (resource kind,
 * actions, roles, data classifications, attributes). A rule that invents an action, role, or
 * classification is rejected even if it is otherwise well-formed and in-subtree.
 */
class GenerationGroundedInManifestTest {

    private final PolicyYamlParser parser = new PolicyYamlParser();
    private final GeneratedPolicyValidator validator = new GeneratedPolicyValidator();

    private PolicyAuthoringRequest acme() {
        return PolicyStudioFixtures.request("Restrict acme agents.", TenantScope.of("acme"), false);
    }

    @Test
    void usesOnlyManifestEntityVocabulary() {
        // Baseline: the golden candidate uses only vocabulary → accepted.
        PolicyIR good = parser.parse(PolicyStudioFixtures.compliantAcme());
        assertThat(validator.validate(good, acme()).accepted()).isTrue();

        // An action not in the manifest vocabulary → rejected.
        PolicyIR badAction = parser.parse(PolicyStudioFixtures.outOfVocabularyAction());
        GeneratedPolicyValidator.Result actionResult = validator.validate(badAction, acme());
        assertThat(actionResult.accepted()).isFalse();
        assertThat(actionResult.violations())
                .anyMatch(v -> v.contains("action 'exfiltrate'") && v.contains("not in the manifest vocabulary"));

        // A data-classification literal not in the manifest vocabulary → rejected.
        PolicyIR badClass = parser.parse(PolicyStudioFixtures.outOfVocabularyClassification());
        GeneratedPolicyValidator.Result classResult = validator.validate(badClass, acme());
        assertThat(classResult.accepted()).isFalse();
        assertThat(classResult.violations())
                .anyMatch(v -> v.contains("top-secret") && v.contains("not in the manifest vocabulary"));
    }
}
