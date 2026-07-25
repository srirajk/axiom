package com.openwolf.iam.policystudio.lifecycle;

import com.openwolf.iam.policystudio.ConsequenceApprovalRecord;
import com.openwolf.iam.policystudio.ConsequenceReview;

/**
 * A locked promotion intent (Axiom Story C5 / onboarding §10). It names the EXACT candidate bundle, the
 * reviewed baseline it was diffed against, the C4 consequence review the human saw, the signed approval
 * over that review's hash, and an idempotency key. Promotion verifies the approval signature over the
 * review hash, stages + compiles + probes the candidate, then compare-and-sets the active version from
 * {@code review.currentBundleId()} to the candidate id.
 *
 * @param candidate      the immutable candidate bundle to activate
 * @param review         the C4 consequence review (binds tenant, both bundle ids, matrix, delta)
 * @param approval       the signed approval over {@code review.consequenceReviewHash()}
 * @param idempotencyKey the lost-response-retry key (a retry returns the same receipt, never double-promotes)
 * @param kind           PROMOTION or ROLLBACK (a rollback is a promotion to a previously certified bundle)
 */
public record PromotionRequest(
        PolicyBundle candidate,
        ConsequenceReview review,
        ConsequenceApprovalRecord approval,
        String idempotencyKey,
        PromotionRecord.Kind kind) {

    public PromotionRequest {
        if (candidate == null) {
            throw new IllegalArgumentException("candidate bundle must be set");
        }
        if (review == null || approval == null) {
            throw new IllegalArgumentException("review and approval must be set");
        }
        if (idempotencyKey == null || idempotencyKey.isBlank()) {
            throw new IllegalArgumentException("idempotencyKey must be set");
        }
        if (kind == null) {
            kind = PromotionRecord.Kind.PROMOTION;
        }
    }

    public String tenantId() {
        return review.tenantId();
    }

    /** The reviewed OLD id the CAS must observe as current (the diff's captured current bundle). */
    public String reviewedCurrentBundleId() {
        return review.currentBundleId();
    }
}
