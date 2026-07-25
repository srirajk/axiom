package com.openwolf.iam.policystudio.lifecycle;

/**
 * The immutable receipt returned by a promotion (Axiom Story C5). On a lost-response retry the SAME
 * receipt comes back with {@code idempotentReplay = true} and no second CAS is performed.
 *
 * @param promotionId      the ledger row id
 * @param tenantId         the tenant promoted
 * @param fromBundleId     the reviewed OLD id the CAS advanced from
 * @param toBundleId       the candidate id now active
 * @param directoryVersion the published directory snapshot version
 * @param kind             PROMOTION or ROLLBACK
 * @param idempotentReplay true iff this receipt is a replay of an earlier promotion with the same key
 */
public record PromotionReceipt(
        String promotionId,
        String tenantId,
        String fromBundleId,
        String toBundleId,
        long directoryVersion,
        PromotionRecord.Kind kind,
        boolean idempotentReplay) {
}
