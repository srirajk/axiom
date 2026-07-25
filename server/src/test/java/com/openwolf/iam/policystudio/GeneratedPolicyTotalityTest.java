package com.openwolf.iam.policystudio;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * C2.4 — every accepted candidate has an explicit opinion (ALLOW or DENY) on EVERY base-ceiling
 * tuple. Under {@code REQUIRE_PARENTAL_CONSENT_FOR_ALLOWS} a tuple the child is silent on falls
 * through and inherits the parent ALLOW (fail-open), so any gap is a rejection.
 */
class GeneratedPolicyTotalityTest {

    private final PolicyYamlParser parser = new PolicyYamlParser();
    private final GeneratedPolicyValidator validator = new GeneratedPolicyValidator();

    private PolicyAuthoringRequest acme() {
        return PolicyStudioFixtures.request("Restrict acme agents.", TenantScope.of("acme"), false);
    }

    @Test
    void coversEveryBaseCeilingTuple() {
        // The golden candidate covers all twelve base tuples → accepted.
        PolicyIR total = parser.parse(PolicyStudioFixtures.compliantAcme());
        assertThat(validator.validate(total, acme()).accepted()).isTrue();

        // Drop (register, domain_admin) + (deregister, domain_admin) → two fall-through holes.
        PolicyIR gappy = parser.parse(PolicyStudioFixtures.omitsBaseTuple());
        GeneratedPolicyValidator.Result result = validator.validate(gappy, acme());
        assertThat(result.accepted()).isFalse();
        assertThat(result.violations())
                .anyMatch(v -> v.contains("register") && v.contains("domain_admin") && v.contains("fall through"))
                .anyMatch(v -> v.contains("deregister") && v.contains("domain_admin") && v.contains("fall through"));
    }
}
