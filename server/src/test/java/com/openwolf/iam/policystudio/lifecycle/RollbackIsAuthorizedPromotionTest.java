package com.openwolf.iam.policystudio.lifecycle;

import com.openwolf.iam.policystudio.ConsequenceApprovalRecord;
import com.openwolf.iam.policystudio.ConsequenceReview;
import com.openwolf.iam.tenancy.ActiveTenantDirectory;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * C5.3 — rollback is a NEW authorized promotion to a previously certified bundle, not a database reversal
 * or a delete (onboarding §11). After promoting current → candidate, a rollback restores `current` via a
 * fresh signed approval and a compare-and-set candidate → current. Both bundles remain immutable and
 * available in the store afterwards.
 */
class RollbackIsAuthorizedPromotionTest {

    @Test
    void rollbackRestoresPriorBundleViaNewPromotion() {
        PolicyBundle current = C5LifecycleFixtures.bundle(C5LifecycleFixtures.currentBody(), C5LifecycleFixtures.matrixHash());
        PolicyBundle candidate = C5LifecycleFixtures.bundle(C5LifecycleFixtures.candidateBody(), C5LifecycleFixtures.matrixHash());

        ActiveTenantDirectory dir = C5LifecycleFixtures.directory();
        dir.activate(C5LifecycleFixtures.TENANT, current.bundleId());

        PromotionRepository promotions = C5LifecycleFixtures.promotionRepo();
        PolicyBundleRepository bundles = C5LifecycleFixtures.bundleRepo();
        ApprovalRepository approvals = C5LifecycleFixtures.approvalRepo();
        // `current` was itself promoted by an earlier lifecycle step — it is in the immutable store.
        bundles.save(new PolicyBundleRecord(current, "commit-0"));

        PolicyPromotionService svc = C5LifecycleFixtures.promotionService(
                dir, promotions, bundles, approvals, C5LifecycleFixtures.passingProbe(), "commit-1");

        // Forward promotion current → candidate.
        ConsequenceReview forward = C5LifecycleFixtures.review(current, candidate);
        ConsequenceApprovalRecord forwardApproval = C5LifecycleFixtures.approve(forward, "sec-reviewer-01");
        svc.promote(new PromotionRequest(candidate, forward, forwardApproval, "promo-fwd", PromotionRecord.Kind.PROMOTION));
        assertThat(dir.find(C5LifecycleFixtures.TENANT)).hasValue(candidate.bundleId());

        // Rollback candidate → current: a fresh review + approval, restoring the previously certified bundle.
        ConsequenceReview rollbackReview = C5LifecycleFixtures.reviewBetween(
                candidate, C5LifecycleFixtures.candidateBody(), current, C5LifecycleFixtures.currentBody());
        ConsequenceApprovalRecord rollbackApproval = C5LifecycleFixtures.approve(rollbackReview, "release-mgr-02");

        PromotionReceipt receipt = svc.rollback(new PromotionRequest(
                current, rollbackReview, rollbackApproval, "rollback-1", PromotionRecord.Kind.ROLLBACK));

        // The prior bundle is restored as the live version.
        assertThat(receipt.kind()).isEqualTo(PromotionRecord.Kind.ROLLBACK);
        assertThat(receipt.toBundleId()).isEqualTo(current.bundleId());
        assertThat(dir.find(C5LifecycleFixtures.TENANT)).hasValue(current.bundleId());

        // NEITHER bundle was deleted — both remain immutable and available (old versions retained).
        assertThat(bundles.existsById(current.bundleId())).isTrue();
        assertThat(bundles.existsById(candidate.bundleId())).isTrue();

        // The rollback is a NEW promotion ledger row (authorized), not a mutation of the forward one.
        assertThat(promotions.findByIdempotencyKey("rollback-1")).isPresent();
        assertThat(promotions.findByIdempotencyKey("rollback-1").orElseThrow().getKind())
                .isEqualTo(PromotionRecord.Kind.ROLLBACK);
        assertThat(promotions.findByTenantIdOrderByCreatedAtDesc(C5LifecycleFixtures.TENANT)).hasSize(2);
    }
}
