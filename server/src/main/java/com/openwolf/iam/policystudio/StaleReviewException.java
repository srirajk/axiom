package com.openwolf.iam.policystudio;

/**
 * Thrown when an approval is attempted against a {@link ConsequenceReview} whose captured current
 * bundle no longer matches the tenant's active bundle (Axiom Story C4.5). The approver must not sign a
 * diff computed against a superseded baseline — a fresh diff against the new current bundle is required
 * first.
 */
public class StaleReviewException extends RuntimeException {
    public StaleReviewException(String message) {
        super(message);
    }
}
