package com.openwolf.iam.policystudio.lifecycle;

import com.openwolf.iam.policystudio.BundleSnapshot;
import com.openwolf.iam.policystudio.ConsequenceDiffService;
import com.openwolf.iam.policystudio.ConsequenceFixtureMatrix;
import com.openwolf.iam.policystudio.ConsequenceReview;
import com.openwolf.iam.policystudio.ManifestVocabulary;
import com.openwolf.iam.policystudio.PdpDecisionSource;
import org.springframework.stereotype.Service;

/**
 * Regeneration (Axiom Story C5.2): produce a NEW immutable candidate bundle and a C4 consequence review
 * (the reviewed diff) against the current bundle, WITHOUT ever mutating a stored or active bundle.
 * Regeneration is a pure function of its inputs — it writes nothing. The current bundle's stored bytes
 * stay byte-identical; the candidate becomes real only through a separate authorized promotion.
 *
 * <p>The diff is the SAME C4 machine truth an approver signs: real PDP decisions against the two
 * immutable snapshots, never an LLM. Authoring-plane only.
 */
@Service
public class RegenerationService {

    private final ConsequenceDiffService diffService;

    public RegenerationService(ConsequenceDiffService diffService) {
        this.diffService = diffService;
    }

    /**
     * Regenerate: diff the candidate against the current bundle and return the new candidate + review.
     *
     * @param currentBundle    the stored/active immutable bundle (NEVER written by this method)
     * @param candidateBundle  the freshly-built immutable candidate (must have a different id)
     * @param vocab            the manifest vocabulary the consequences are phrased over
     * @param currentSnapshot  the C4 snapshot of the current bundle (for the PDP diff)
     * @param candidateSnapshot the C4 snapshot of the candidate bundle (for the PDP diff)
     * @param matrix           the sampled fixture matrix the diff is computed over
     * @param source           the PDP decision source (real Cerbos or the in-process fidelity evaluator)
     * @throws IllegalArgumentException if regeneration produced no new bundle (same id as the current)
     */
    public RegenerationResult regenerate(PolicyBundle currentBundle, PolicyBundle candidateBundle,
                                         ManifestVocabulary vocab, BundleSnapshot currentSnapshot,
                                         BundleSnapshot candidateSnapshot, ConsequenceFixtureMatrix matrix,
                                         PdpDecisionSource source) {
        if (candidateBundle.bundleId().equals(currentBundle.bundleId())) {
            throw new IllegalArgumentException(
                    "regeneration produced no new bundle: candidate id equals current id '"
                            + currentBundle.bundleId() + "'");
        }
        ConsequenceReview diff = diffService.computeReview(
                currentBundle.tenantId(), vocab, currentSnapshot, candidateSnapshot, matrix, source);
        // NOTE: nothing is persisted or mutated here — the stored/active bundle is untouched until promote.
        return new RegenerationResult(candidateBundle, diff);
    }
}
