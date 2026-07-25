package com.openwolf.iam.policystudio.lifecycle;

/**
 * Thrown when a promotion is attempted without a valid approval signature over the exact C4
 * {@code consequenceReviewHash} the candidate was reviewed under (Axiom Story C5.3). A missing, rejected,
 * tampered, or mismatched approval leaves the candidate inactive.
 */
public class UnauthorizedPromotionException extends RuntimeException {
    public UnauthorizedPromotionException(String message) {
        super(message);
    }
}
