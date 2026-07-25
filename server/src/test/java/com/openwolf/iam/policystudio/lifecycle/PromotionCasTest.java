package com.openwolf.iam.policystudio.lifecycle;

import com.openwolf.iam.policystudio.ConsequenceApprovalRecord;
import com.openwolf.iam.policystudio.ConsequenceReview;
import com.openwolf.iam.tenancy.ActiveTenantDirectory;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * C5.5 — a reviewed baseline that was superseded cannot activate. If the tenant's active bundle changed
 * after the C4 review was computed, the promotion compare-and-set (reviewed OLD id → candidate id) fails
 * because the directory's current id is no longer the reviewed OLD id. The candidate stays inactive and a
 * fresh diff/approval against the new current bundle is required.
 */
class PromotionCasTest {

    @Test
    void staleReviewedBaseCannotActivate() {
        PolicyBundle current = C5LifecycleFixtures.bundle(C5LifecycleFixtures.currentBody(), C5LifecycleFixtures.matrixHash());
        PolicyBundle candidate = C5LifecycleFixtures.bundle(C5LifecycleFixtures.candidateBody(), C5LifecycleFixtures.matrixHash());
        ConsequenceReview review = C5LifecycleFixtures.review(current, candidate);
        ConsequenceApprovalRecord approval = C5LifecycleFixtures.approve(review, "sec-reviewer-01");

        ActiveTenantDirectory dir = C5LifecycleFixtures.directory();
        dir.activate(C5LifecycleFixtures.TENANT, current.bundleId());

        PromotionRepository promotions = C5LifecycleFixtures.promotionRepo();
        PolicyPromotionService svc = C5LifecycleFixtures.promotionService(
                dir, promotions, C5LifecycleFixtures.bundleRepo(),
                C5LifecycleFixtures.approvalRepo(), C5LifecycleFixtures.passingProbe(), "commit-1");

        // AFTER the review was computed, another promotion advances the active bundle to a THIRD version.
        PolicyBundle interloper = C5LifecycleFixtures.bundle(C5LifecycleFixtures.candidateBody(), "a-different-fixture-set-hash");
        assertThat(interloper.bundleId()).isNotEqualTo(candidate.bundleId());
        dir.compareAndActivate(C5LifecycleFixtures.TENANT, current.bundleId(), interloper.bundleId());
        assertThat(dir.find(C5LifecycleFixtures.TENANT)).hasValue(interloper.bundleId());

        // Promoting the candidate reviewed against the now-superseded `current` must fail the CAS.
        assertThatThrownBy(() -> svc.promote(new PromotionRequest(
                candidate, review, approval, "promo-key-stale", PromotionRecord.Kind.PROMOTION)))
                .isInstanceOf(StalePromotionException.class);

        // The candidate was NOT activated; the interloper remains live.
        assertThat(dir.find(C5LifecycleFixtures.TENANT)).hasValue(interloper.bundleId());

        // The failed promotion is recorded FAILED — a new diff/approval is required to proceed.
        PromotionRecord op = promotions.findByIdempotencyKey("promo-key-stale").orElseThrow();
        assertThat(op.getStatus()).isEqualTo(PromotionRecord.Status.FAILED);
        assertThat(op.getLastError()).contains("stale");
    }
}
