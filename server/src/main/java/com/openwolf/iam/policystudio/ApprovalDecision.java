package com.openwolf.iam.policystudio;

/**
 * A human's decision on a {@link ConsequenceReview} (Axiom Story C4). The approver acts on business
 * consequences, not YAML; the decision is bound to the exact {@code consequenceReviewHash} they saw.
 */
public enum ApprovalDecision {
    APPROVE,
    REJECT
}
