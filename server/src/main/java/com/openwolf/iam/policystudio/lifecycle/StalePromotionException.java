package com.openwolf.iam.policystudio.lifecycle;

/**
 * Thrown when the promotion compare-and-set is refused because the tenant's active bundle changed after
 * the reviewed baseline (Axiom Story C5.5). The reviewed OLD id no longer equals the directory's current
 * id, so activating would silently cross a version the human never reviewed — a fresh C4 diff + approval
 * against the new current bundle is required. The candidate stays inactive.
 */
public class StalePromotionException extends RuntimeException {
    public StalePromotionException(String message) {
        super(message);
    }
}
