package com.openwolf.iam.policystudio.breakglass;

import com.openwolf.iam.policystudio.CanonicalPolicyWriter;
import com.openwolf.iam.policystudio.GeneratedPolicyValidator;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * C6.2 — a break-glass artifact naming ANOTHER tenant is rejected at C2's segment-wise scope check.
 * Break-glass reuses the exact C2 {@link GeneratedPolicyValidator} scope containment, so it is
 * STRUCTURALLY unable to grant emergency access outside the author's own tenant subtree — a naive
 * string-prefix ({@code acme} vs {@code acme-evil}) does not escape either, because containment is
 * decided segment-by-segment.
 */
class BreakGlassCannotCrossTenantTest {

    private final BreakGlassAuthoringService svc = new BreakGlassAuthoringService(
            new BreakGlassValidator(60),
            new BreakGlassPolicyCompiler(),
            new GeneratedPolicyValidator(),
            new CanonicalPolicyWriter());

    @Test
    void ownTenantGrantIsAdmissible() {
        BreakGlassArtifact art = svc.author(
                BreakGlassFixtures.grant("acme", 900, "alice"),
                BreakGlassFixtures.allowlist(),
                BreakGlassFixtures.request("acme"));
        assertThat(art.boundsResult().accepted()).isTrue();
        assertThat(art.c2Result().accepted()).as("c2 violations: %s", art.c2Result().violations()).isTrue();
        assertThat(art.admissible()).isTrue();
    }

    @Test
    void namingAnotherTenantIsRejectedAtScopeCheck() {
        BreakGlassArtifact art = svc.author(
                BreakGlassFixtures.grant("beta", 900, "alice"),   // author is "acme"
                BreakGlassFixtures.allowlist(),
                BreakGlassFixtures.request("acme"));
        assertThat(art.admissible()).isFalse();
        assertThat(art.c2Result().accepted()).isFalse();
        assertThat(art.c2Result().violations())
                .anySatisfy(v -> assertThat(v).contains("escapes the author's subtree"));
    }

    @Test
    void siblingByStringPrefixIsAlsoRejected() {
        // "acme-evil" is a single segment distinct from "acme" — a startsWith() check would be fooled;
        // C2's segment-wise containment is not.
        BreakGlassArtifact art = svc.author(
                BreakGlassFixtures.grant("acme-evil", 900, "alice"),
                BreakGlassFixtures.allowlist(),
                BreakGlassFixtures.request("acme"));
        assertThat(art.admissible()).isFalse();
        assertThat(art.c2Result().violations())
                .anySatisfy(v -> assertThat(v).contains("escapes the author's subtree"));
    }
}
