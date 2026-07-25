package com.openwolf.iam.policystudio.lifecycle;

import com.openwolf.iam.policystudio.ConsequenceApprovalRecord;
import com.openwolf.iam.policystudio.ConsequenceReview;
import com.openwolf.iam.tenancy.ActiveTenantDirectory;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Axiom H2 — {@link PolicyPromotionService#promote} re-validates the candidate UNCONDITIONALLY and never
 * degrades. It proves:
 *
 * <ul>
 *   <li>a candidate with a wildcard grant ({@code roles:["*"]}) is rejected at promote();</li>
 *   <li>a candidate whose scope escapes the author's subtree (a sibling tenant) is rejected;</li>
 *   <li>a candidate that omits a base-ceiling DENY/ALLOW tuple (fail-open hole) is rejected;</li>
 *   <li>a tampered consequence-review hash is rejected server-side (recomputed from the truth fields);</li>
 *   <li>a Cerbos-down probe REFUSES the promotion — never version-stamp-only — leaving the tenant on its
 *       current bundle.</li>
 * </ul>
 *
 * Before H2, promote() never called {@code GeneratedPolicyValidator}, never recomputed the review hash,
 * and skipped the compile probe when Cerbos was absent (version-stamp-only). All three holes are closed.
 */
class PromotionRevalidationTest {

    // ── adversarial candidate bodies (version "default"; C5LifecycleFixtures stamps the sentinel) ──

    /** A wildcard grant — {@code actions:["*"]}, {@code roles:["*"]}. */
    private static String wildcardGrantBody() {
        return """
                apiVersion: api.cerbos.dev/v1
                resourcePolicy:
                  version: "default"
                  resource: agent
                  scope: "acme"
                  scopePermissions: SCOPE_PERMISSIONS_REQUIRE_PARENTAL_CONSENT_FOR_ALLOWS
                  rules:
                    - actions: ["*"]
                      effect: EFFECT_ALLOW
                      roles: ["*"]
                """;
    }

    /** Scope escapes the author's subtree (author is `acme`, this targets sibling tenant `beta`). */
    private static String siblingTenantScopeBody() {
        return """
                apiVersion: api.cerbos.dev/v1
                resourcePolicy:
                  version: "default"
                  resource: agent
                  scope: "beta"
                  scopePermissions: SCOPE_PERMISSIONS_REQUIRE_PARENTAL_CONSENT_FOR_ALLOWS
                  rules:
                    - actions: ["invoke", "invoke_membership", "register", "deregister"]
                      effect: EFFECT_ALLOW
                      roles: ["platform_admin"]
                    - actions: ["invoke", "invoke_membership", "register", "deregister"]
                      effect: EFFECT_ALLOW
                      roles: ["domain_admin"]
                    - actions: ["invoke", "invoke_membership"]
                      effect: EFFECT_ALLOW
                      roles: ["chat_user", "relationship_manager"]
                """;
    }

    /** Omits the (register/deregister, domain_admin) tuples — a base-ceiling fall-through hole. */
    private static String omitsBaseTupleBody() {
        return """
                apiVersion: api.cerbos.dev/v1
                resourcePolicy:
                  version: "default"
                  resource: agent
                  scope: "acme"
                  scopePermissions: SCOPE_PERMISSIONS_REQUIRE_PARENTAL_CONSENT_FOR_ALLOWS
                  rules:
                    - actions: ["invoke", "invoke_membership", "register", "deregister"]
                      effect: EFFECT_ALLOW
                      roles: ["platform_admin"]
                    - actions: ["invoke", "invoke_membership"]
                      effect: EFFECT_ALLOW
                      roles: ["domain_admin"]
                    - actions: ["invoke", "invoke_membership"]
                      effect: EFFECT_ALLOW
                      roles: ["chat_user", "relationship_manager"]
                """;
    }

    private PolicyPromotionService serviceOn(ActiveTenantDirectory dir, PolicyBundle current) {
        dir.activate(C5LifecycleFixtures.TENANT, current.bundleId());
        return C5LifecycleFixtures.promotionService(
                dir, C5LifecycleFixtures.promotionRepo(), C5LifecycleFixtures.bundleRepo(),
                C5LifecycleFixtures.approvalRepo(), C5LifecycleFixtures.passingProbe(), "commit-1");
    }

    private void assertBadCandidateRejected(String badBody) {
        PolicyBundle current = C5LifecycleFixtures.bundle(
                C5LifecycleFixtures.currentBody(), C5LifecycleFixtures.matrixHash());
        PolicyBundle candidate = C5LifecycleFixtures.bundle(badBody, C5LifecycleFixtures.matrixHash());

        ActiveTenantDirectory dir = C5LifecycleFixtures.directory();
        PolicyPromotionService svc = serviceOn(dir, current);

        ConsequenceReview review = C5LifecycleFixtures.handReview(current, candidate);
        ConsequenceApprovalRecord approval = C5LifecycleFixtures.approve(review, "sec-reviewer-01");

        assertThatThrownBy(() -> svc.promote(new PromotionRequest(
                candidate, review, approval, "promo-bad-" + candidate.bundleId(), PromotionRecord.Kind.PROMOTION)))
                .isInstanceOf(PolicyRevalidationException.class);

        // The candidate never activated — the tenant stays on its current bundle.
        assertThat(dir.find(C5LifecycleFixtures.TENANT)).hasValue(current.bundleId());
    }

    @Test
    void wildcardGrantIsRejectedAtPromote() {
        assertBadCandidateRejected(wildcardGrantBody());
    }

    @Test
    void siblingTenantScopeIsRejectedAtPromote() {
        assertBadCandidateRejected(siblingTenantScopeBody());
    }

    @Test
    void omittedBaseTupleIsRejectedAtPromote() {
        assertBadCandidateRejected(omitsBaseTupleBody());
    }

    @Test
    void tamperedReviewHashIsRejectedServerSide() {
        PolicyBundle current = C5LifecycleFixtures.bundle(
                C5LifecycleFixtures.currentBody(), C5LifecycleFixtures.matrixHash());
        PolicyBundle candidate = C5LifecycleFixtures.bundle(
                C5LifecycleFixtures.candidateBody(), C5LifecycleFixtures.matrixHash());

        ActiveTenantDirectory dir = C5LifecycleFixtures.directory();
        PolicyPromotionService svc = serviceOn(dir, current);

        // A valid approval over the GOOD review (same candidate) — so step 1 (candidate id) matches …
        ConsequenceReview good = C5LifecycleFixtures.handReview(current, candidate);
        ConsequenceApprovalRecord approval = C5LifecycleFixtures.approve(good, "sec-reviewer-01");
        // … but the review handed to promote() carries a tampered hash (recompute != stored).
        ConsequenceReview tampered = C5LifecycleFixtures.tamperedReview(current, candidate);

        assertThatThrownBy(() -> svc.promote(new PromotionRequest(
                candidate, tampered, approval, "promo-tamper", PromotionRecord.Kind.PROMOTION)))
                .isInstanceOf(UnauthorizedPromotionException.class)
                .hasMessageContaining("tampered review");

        assertThat(dir.find(C5LifecycleFixtures.TENANT)).hasValue(current.bundleId());
    }

    @Test
    void cerbosDownRefusesPromotionNeverStampsOnly() {
        PolicyBundle current = C5LifecycleFixtures.bundle(
                C5LifecycleFixtures.currentBody(), C5LifecycleFixtures.matrixHash());
        PolicyBundle candidate = C5LifecycleFixtures.bundle(
                C5LifecycleFixtures.candidateBody(), C5LifecycleFixtures.matrixHash());

        ActiveTenantDirectory dir = C5LifecycleFixtures.directory();
        dir.activate(C5LifecycleFixtures.TENANT, current.bundleId());

        // The mandatory cerbos-compile probe hard-fails when Cerbos is unavailable.
        PolicyPromotionService svc = C5LifecycleFixtures.promotionService(
                dir, C5LifecycleFixtures.promotionRepo(), C5LifecycleFixtures.bundleRepo(),
                C5LifecycleFixtures.approvalRepo(), C5LifecycleFixtures.cerbosDownProbe(), "commit-1");

        ConsequenceReview review = C5LifecycleFixtures.review(current, candidate);
        ConsequenceApprovalRecord approval = C5LifecycleFixtures.approve(review, "sec-reviewer-01");

        assertThatThrownBy(() -> svc.promote(new PromotionRequest(
                candidate, review, approval, "promo-cerbos-down", PromotionRecord.Kind.PROMOTION)))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("MANDATORY");

        // NOT stamped: the tenant is still on its current bundle.
        assertThat(dir.find(C5LifecycleFixtures.TENANT)).hasValue(current.bundleId());
    }
}
