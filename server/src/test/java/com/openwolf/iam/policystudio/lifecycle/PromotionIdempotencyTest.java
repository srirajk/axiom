package com.openwolf.iam.policystudio.lifecycle;

import com.openwolf.iam.policystudio.ConsequenceApprovalRecord;
import com.openwolf.iam.policystudio.ConsequenceReview;
import com.openwolf.iam.tenancy.ActiveTenantDirectory;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * C5.3 — a lost-response retry does not double-promote (onboarding §10). The first promotion flips the
 * live pointer and stores the immutable bundle; a retry with the SAME idempotency key returns the same
 * receipt as a replay and drives NO second compare-and-set (the directory version does not advance).
 */
class PromotionIdempotencyTest {

    @Test
    void retryIsIdempotent() {
        PolicyBundle current = C5LifecycleFixtures.bundle(C5LifecycleFixtures.currentBody(), C5LifecycleFixtures.matrixHash());
        PolicyBundle candidate = C5LifecycleFixtures.bundle(C5LifecycleFixtures.candidateBody(), C5LifecycleFixtures.matrixHash());
        ConsequenceReview review = C5LifecycleFixtures.review(current, candidate);
        ConsequenceApprovalRecord approval = C5LifecycleFixtures.approve(review, "sec-reviewer-01");

        ActiveTenantDirectory dir = C5LifecycleFixtures.directory();
        dir.activate(C5LifecycleFixtures.TENANT, current.bundleId());

        PromotionRepository promotions = C5LifecycleFixtures.promotionRepo();
        PolicyBundleRepository bundles = C5LifecycleFixtures.bundleRepo();
        ApprovalRepository approvals = C5LifecycleFixtures.approvalRepo();
        PolicyPromotionService svc = C5LifecycleFixtures.promotionService(
                dir, promotions, bundles, approvals, C5LifecycleFixtures.passingProbe(), "commit-1");

        PromotionRequest request = new PromotionRequest(
                candidate, review, approval, "promo-key-1", PromotionRecord.Kind.PROMOTION);

        PromotionReceipt first = svc.promote(request);
        assertThat(first.idempotentReplay()).isFalse();
        assertThat(first.toBundleId()).isEqualTo(candidate.bundleId());
        assertThat(dir.find(C5LifecycleFixtures.TENANT)).hasValue(candidate.bundleId());
        long versionAfterFirst = dir.version();
        assertThat(bundles.existsById(candidate.bundleId())).isTrue();

        // Retry the SAME request (lost response) — replay, no second CAS.
        PromotionReceipt retry = svc.promote(request);
        assertThat(retry.idempotentReplay()).isTrue();
        assertThat(retry.toBundleId()).isEqualTo(candidate.bundleId());
        assertThat(retry.promotionId()).isEqualTo(first.promotionId());

        // The directory did NOT advance a second time, and the tenant is still on the candidate.
        assertThat(dir.version()).isEqualTo(versionAfterFirst);
        assertThat(dir.find(C5LifecycleFixtures.TENANT)).hasValue(candidate.bundleId());

        // Exactly one promotion ledger row for the key, and it is PROMOTED.
        PromotionRecord op = promotions.findByIdempotencyKey("promo-key-1").orElseThrow();
        assertThat(op.getStatus()).isEqualTo(PromotionRecord.Status.PROMOTED);
        assertThat(promotions.findByTenantIdOrderByCreatedAtDesc(C5LifecycleFixtures.TENANT)).hasSize(1);

        assertThatThrownBy(() -> svc.replayCompleted("promo-key-1", "other-tenant",
                current.bundleId(), candidate.bundleId(), review.consequenceReviewHash(),
                "sec-reviewer-01", PromotionRecord.Kind.PROMOTION))
                .isInstanceOf(UnauthorizedPromotionException.class)
                .hasMessageContaining("different tenant");
        assertThatThrownBy(() -> svc.replayCompleted("promo-key-1", C5LifecycleFixtures.TENANT,
                current.bundleId(), candidate.bundleId(), review.consequenceReviewHash(),
                "sec-reviewer-01", PromotionRecord.Kind.ROLLBACK))
                .isInstanceOf(UnauthorizedPromotionException.class);
    }
}
