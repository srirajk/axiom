package com.openwolf.iam.policystudio;

import java.time.Instant;
import java.util.List;

/**
 * The typed data contract the consequence-review SPA renders (Axiom Story C4 — the adoption unlock:
 * a non-engineer approves business <em>consequences</em>, not YAML). It is produced entirely by
 * {@link ConsequenceDiffService} from real PDP decisions; the React surface that renders it is a
 * separate product surface (HELD for the user — see the C4 evidence README).
 *
 * <p><b>Truth vs display are separated.</b> The machine truth — {@code deltas}, {@code overPermissionAlarm},
 * {@code canonicalDelta}, {@code consequenceReviewHash} — is computed from PDP decisions and NOTHING
 * else. {@code displayProse} is optional LLM-phrased text ({@link ConsequenceProseModelClient}); it is
 * outside the hash, so display wording can never alter the signed consequences (C4.6). An approval
 * record signs {@code consequenceReviewHash}; promotion accepts only the exact
 * current/candidate/review-hash tuple the human saw.
 *
 * @param tenantId              the tenant whose bundle is under review
 * @param resourceKind          the manifest entity the consequences are phrased over (World B vocab)
 * @param currentBundleId       the captured current (active) bundle the diff was computed against
 * @param candidateBundleId     the staged candidate bundle
 * @param fixtureSetHash        the sampled matrix the diff was computed over
 * @param deltas                the changed cells, each a business consequence (empty ⇒ no-op candidate)
 * @param overPermissionAlarm   {@code true} iff any delta is DENY→ALLOW (widening) — the loud alarm
 * @param principalsGainingAccess the count of widening (DENY→ALLOW) deltas — "N principals GAIN access"
 * @param canonicalDelta        the canonical machine delta the hash is computed over
 * @param consequenceReviewHash sha256(tenantId, currentBundleId, candidateBundleId, fixtureSetHash, canonicalDelta)
 * @param disclosure            the first-class sampled-not-formal disclosure
 * @param provenance            the real PDP decision batches for both snapshots (audit/replay)
 * @param generatedAt           when the review was computed
 * @param displayProse          optional LLM-phrased display text; {@code null} if not (or could not be) phrased
 */
public record ConsequenceReview(
        String tenantId,
        String resourceKind,
        String currentBundleId,
        String candidateBundleId,
        String fixtureSetHash,
        List<ConsequenceDelta> deltas,
        boolean overPermissionAlarm,
        int principalsGainingAccess,
        String canonicalDelta,
        String consequenceReviewHash,
        SampledDisclosure disclosure,
        PdpProvenance provenance,
        Instant generatedAt,
        String displayProse) {

    public ConsequenceReview {
        deltas = List.copyOf(deltas);
    }

    /**
     * Attach LLM-phrased display prose WITHOUT touching any truth field — the hash is unchanged, so an
     * approval signed against this review stays valid regardless of the wording (C4.6). Returns a copy;
     * the review is immutable.
     */
    public ConsequenceReview withProse(String prose) {
        return new ConsequenceReview(
                tenantId, resourceKind, currentBundleId, candidateBundleId, fixtureSetHash, deltas,
                overPermissionAlarm, principalsGainingAccess, canonicalDelta, consequenceReviewHash,
                disclosure, provenance, generatedAt, prose);
    }

    /** The widening (over-permission) deltas — the ones the alarm counts. */
    public List<ConsequenceDelta> wideningDeltas() {
        return deltas.stream().filter(ConsequenceDelta::overPermission).toList();
    }

    /** Recompute the review hash from the truth fields — used by the approval gate to detect tampering. */
    public String recomputeHash() {
        return ConsequenceDiffService.reviewHash(
                tenantId, currentBundleId, candidateBundleId, fixtureSetHash, canonicalDelta);
    }
}
