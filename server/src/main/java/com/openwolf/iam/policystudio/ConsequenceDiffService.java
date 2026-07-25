package com.openwolf.iam.policystudio;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * The consequence-diff service (Axiom Story C4 — the adoption unlock). It computes the decision delta a
 * candidate bundle would introduce, as business consequences a non-engineer can approve, and binds an
 * approval to the exact machine consequences.
 *
 * <p><b>How the truth is produced (and where the LLM is NOT):</b>
 * <ol>
 *   <li>Run real PDP evaluations of the SAME sampled fixture matrix against BOTH immutable snapshots —
 *       the request's captured current bundle and the staged candidate — through a
 *       {@link PdpDecisionSource} (the pinned Cerbos, or the in-process C3 fidelity evaluator).
 *       <b>The live pointer is never swapped to compute a diff.</b></li>
 *   <li>Diff the two real answer sets per cell. A changed cell is a {@link ConsequenceDelta};
 *       DENY→ALLOW is the loud over-permission alarm.</li>
 *   <li>Canonicalise the machine delta and compute
 *       {@code consequenceReviewHash = sha256(tenantId, currentBundleId, candidateBundleId, fixtureSetHash, canonicalDelta)}.</li>
 *   <li>Phrase each consequence over the manifest entity vocabulary (World B).</li>
 * </ol>
 * <b>No LLM touches steps 1–4.</b> An LLM may only later phrase the finished delta into display prose
 * ({@link #attachProse}); a phrasing failure leaves the review fully correct (C4.1).
 *
 * <p><b>Boundary (C4):</b> authoring-plane only; {@code PolicyAuthoringBoundaryArchTest} proves no
 * runtime-enforcement code can reach this service or the prose seam.
 */
@Service
public class ConsequenceDiffService {

    private static final Logger log = LoggerFactory.getLogger(ConsequenceDiffService.class);

    /**
     * Compute the consequence review for a candidate against the captured current bundle, over a sampled
     * fixture matrix, using real PDP decisions. Never calls an LLM.
     */
    public ConsequenceReview computeReview(
            String tenantId,
            ManifestVocabulary vocab,
            BundleSnapshot current,
            BundleSnapshot candidate,
            ConsequenceFixtureMatrix matrix,
            PdpDecisionSource source) {

        if (tenantId == null || tenantId.isBlank()) {
            throw new IllegalArgumentException("tenantId must be set");
        }
        // (1) real PDP evaluations against two immutable snapshots — truth comes from the PDP.
        PdpBatchResult currentBatch = source.evaluate(current, matrix.cells());
        PdpBatchResult candidateBatch = source.evaluate(candidate, matrix.cells());
        Map<String, Effect> before = currentBatch.byCell();
        Map<String, Effect> after = candidateBatch.byCell();

        // (2) diff per cell (matrix order for stable presentation).
        List<ConsequenceDelta> deltas = new ArrayList<>();
        int gaining = 0;
        for (FixtureCell cell : matrix.cells()) {
            Effect from = before.get(cell.label());
            Effect to = after.get(cell.label());
            if (from == null || to == null) {
                throw new IllegalStateException("PDP source did not decide cell '" + cell.label() + "'");
            }
            if (from == to) {
                continue; // unchanged cells are never deltas
            }
            DeltaDirection direction = (from == Effect.DENY && to == Effect.ALLOW)
                    ? DeltaDirection.WIDENED : DeltaDirection.NARROWED;
            boolean overPermission = direction == DeltaDirection.WIDENED;
            if (overPermission) {
                gaining++;
            }
            deltas.add(new ConsequenceDelta(cell, from, to, direction, overPermission,
                    renderConsequence(cell, direction, vocab)));
        }

        // (3) canonicalise the machine delta (sorted, order-independent) and hash it.
        String canonicalDelta = canonicalise(deltas);
        String hash = reviewHash(tenantId, current.bundleId(), candidate.bundleId(),
                matrix.fixtureSetHash(), canonicalDelta);

        boolean alarm = gaining > 0;
        log.debug("C4 consequence review: tenant={} deltas={} widening={} alarm={} hash={}",
                tenantId, deltas.size(), gaining, alarm, hash);

        return new ConsequenceReview(
                tenantId,
                vocab.resourceKind(),
                current.bundleId(),
                candidate.bundleId(),
                matrix.fixtureSetHash(),
                deltas,
                alarm,
                gaining,
                canonicalDelta,
                hash,
                SampledDisclosure.over(matrix.cells().size()),
                new PdpProvenance(source.sourceId(), currentBatch, candidateBatch),
                Instant.now(),
                null);
    }

    /**
     * Optionally phrase the finished review's delta into display prose via an LLM seam. If the seam
     * errors, the ORIGINAL review is returned untouched (prose stays absent) — proving the LLM is not
     * in the truth path (C4.1). The hash is never affected either way (C4.6).
     */
    public ConsequenceReview attachProse(ConsequenceReview review, ConsequenceProseModelClient prose) {
        try {
            String text = prose.phrase(review);
            return review.withProse(text);
        } catch (RuntimeException e) {
            log.warn("consequence prose phrasing failed — review remains valid without display prose", e);
            return review;
        }
    }

    /**
     * Render one changed cell as a business consequence over the tenant's MANIFEST ENTITY VOCABULARY
     * (World B): the resource kind, roles and action all come from {@link ManifestVocabulary} / the cell
     * — no domain literal is hardcoded here. The verbs ("GAIN"/"LOSE"/"access") are generic English.
     */
    private String renderConsequence(FixtureCell cell, DeltaDirection direction, ManifestVocabulary vocab) {
        String roles = String.join(", ", new java.util.TreeSet<>(cell.principalRoles()));
        String crossTenant = cell.isCrossTenant()
                ? " ACROSS tenants (principal tenant '" + cell.principalTenant()
                        + "' ≠ resource tenant '" + cell.resourceTenant() + "')"
                : "";
        if (direction == DeltaDirection.WIDENED) {
            return "Principals holding role(s) [" + roles + "] GAIN '" + cell.action()
                    + "' access to " + vocab.resourceKind() + crossTenant
                    + " — currently denied, would be allowed.";
        }
        return "Principals holding role(s) [" + roles + "] LOSE '" + cell.action()
                + "' access to " + vocab.resourceKind() + crossTenant
                + " — currently allowed, would be denied.";
    }

    /** Canonical machine delta: sorted delta rows, one per line — order-independent for a stable hash. */
    private String canonicalise(List<ConsequenceDelta> deltas) {
        return deltas.stream()
                .map(ConsequenceDelta::canonicalRow)
                .sorted()
                .reduce((a, b) -> a + "\n" + b)
                .orElse("<no-op: candidate introduces no decision change>");
    }

    /**
     * The review hash the approval record signs. Binds the tenant, BOTH bundle ids, the sampled matrix,
     * and the canonical machine delta. Changing the candidate, the current bundle, the fixture set, or a
     * single delta cell changes this hash and invalidates any approval; changing only display wording
     * does not (display prose is not an input).
     */
    public static String reviewHash(String tenantId, String currentBundleId, String candidateBundleId,
                                    String fixtureSetHash, String canonicalDelta) {
        String payload = "consequence-review-v1"
                + "\ntenant=" + tenantId
                + "\ncurrent=" + currentBundleId
                + "\ncandidate=" + candidateBundleId
                + "\nfixtureSet=" + fixtureSetHash
                + "\ndelta=\n" + canonicalDelta;
        return "crh-" + StudioHashing.sha256Hex(payload);
    }
}
