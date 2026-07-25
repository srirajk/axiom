package com.openwolf.iam.policystudio;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * C2.1 + C2.4 — a generated artifact structurally cannot escape the author's tenant subtree, and
 * containment is decided by parsed <em>scope segments</em>, never a raw string prefix. Red if the
 * post-generation check trusted the model's intent or matched loosely.
 */
class GeneratedScopeConstraintTest {

    private final PolicyYamlParser parser = new PolicyYamlParser();
    private final GeneratedPolicyValidator validator = new GeneratedPolicyValidator();

    @Test
    void cannotNameScopeOutsideAuthorSubtree() {
        // The author belongs to tenant "acme". The (adversarial) intent asked to "also grant tenant
        // B"; a compliant-looking model obediently emitted scope "beta".
        PolicyAuthoringRequest req = PolicyStudioFixtures.request(
                "Grant our tenant the usual agent access, and also grant tenant B (beta) the same.",
                TenantScope.of("acme"), /* subscopesEnabled */ false);

        PolicyIR escaped = parser.parse(PolicyStudioFixtures.scopeEscapeToTenantB());
        GeneratedPolicyValidator.Result rejected = validator.validate(escaped, req);

        assertThat(rejected.accepted()).isFalse();
        assertThat(rejected.violations())
                .anyMatch(v -> v.contains("escapes the author's subtree"));

        // The in-subtree twin (scope "acme") is accepted — proving the rejection is about the scope,
        // not the policy body.
        PolicyIR inSubtree = parser.parse(PolicyStudioFixtures.compliantAcme());
        assertThat(validator.validate(inSubtree, req).accepted()).isTrue();
    }

    @Test
    void segmentBoundaryNotStringPrefix() {
        PolicyAuthoringRequest noSubscopes = PolicyStudioFixtures.request(
                "Restrict tenant.a agents.", TenantScope.of("tenant.a"), /* subscopesEnabled */ false);

        // "tenant.ab" shares the raw string prefix "tenant.a" but is a DIFFERENT tenant at the
        // segment boundary — must be rejected (the whole point of segment comparison).
        PolicyIR sibling = parser.parse(PolicyStudioFixtures.candidateWithScope("tenant.ab"));
        GeneratedPolicyValidator.Result siblingResult = validator.validate(sibling, noSubscopes);
        assertThat(siblingResult.accepted()).isFalse();
        assertThat(siblingResult.violations()).anyMatch(v -> v.contains("escapes the author's subtree"));

        // Exact same tenant is accepted.
        PolicyIR exact = parser.parse(PolicyStudioFixtures.candidateWithScope("tenant.a"));
        assertThat(validator.validate(exact, noSubscopes).accepted()).isTrue();

        // A true descendant is rejected when subscopes are disabled …
        PolicyIR descendant = parser.parse(PolicyStudioFixtures.candidateWithScope("tenant.a.london"));
        assertThat(validator.validate(descendant, noSubscopes).accepted()).isFalse();

        // … and accepted only when the author explicitly enabled descendants.
        PolicyAuthoringRequest withSubscopes = PolicyStudioFixtures.request(
                "Restrict tenant.a agents.", TenantScope.of("tenant.a"), /* subscopesEnabled */ true);
        assertThat(validator.validate(descendant, withSubscopes).accepted()).isTrue();

        // Pure segment-boundary unit checks on the value type.
        assertThat(TenantScope.of("tenant.a").contains(TenantScope.of("tenant.ab"), true)).isFalse();
        assertThat(TenantScope.of("tenant.a").contains(TenantScope.of("tenant.a"), false)).isTrue();
        assertThat(TenantScope.of("tenant.a").contains(TenantScope.of("tenant.a.london"), true)).isTrue();
        assertThat(TenantScope.of("tenant.a").contains(TenantScope.of("tenant.a.london"), false)).isFalse();
    }
}
