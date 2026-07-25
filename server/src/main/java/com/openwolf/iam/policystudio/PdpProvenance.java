package com.openwolf.iam.policystudio;

/**
 * The real-PDP evidence a {@link ConsequenceReview} carries so the delta is auditable and replayable
 * (Axiom Story C4): the PDP source id, and the full per-cell decision batch for BOTH immutable
 * snapshots (the captured current bundle and the staged candidate). Persisting both raw batches —
 * with their call ids — is what lets an auditor re-run the exact evaluation and reproduce every truth
 * value the diff was built from.
 *
 * @param sourceId       the PDP that produced the decisions (e.g. {@code cerbos:0.53.0})
 * @param currentBatch   every cell decision against the captured current bundle
 * @param candidateBatch every cell decision against the staged candidate bundle
 */
public record PdpProvenance(String sourceId, PdpBatchResult currentBatch, PdpBatchResult candidateBatch) {

    public PdpProvenance {
        if (sourceId == null || sourceId.isBlank()) {
            throw new IllegalArgumentException("sourceId must be set");
        }
        if (currentBatch == null || candidateBatch == null) {
            throw new IllegalArgumentException("both current and candidate batches must be present");
        }
    }
}
