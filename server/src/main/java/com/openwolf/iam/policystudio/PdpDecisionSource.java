package com.openwolf.iam.policystudio;

import java.util.List;

/**
 * The port the consequence-diff service reads ground truth from (Axiom Story C4). A source evaluates a
 * {@link BundleSnapshot} over a batch of {@link FixtureCell}s and returns the real decisions — the
 * truth values the diff is built from. <b>Truth comes from a policy decision point, never from an
 * LLM.</b>
 *
 * <p>Two implementations sit behind this port:
 * <ul>
 *   <li>{@link CerbosBatchDecisionSource} — the real PDP: an EPHEMERAL {@code docker run --rm} of the
 *       pinned Cerbos ({@code 0.53.0}, the runtime PDP version) running a {@code CheckResources}-shaped
 *       batch on a distinct container/temp dir, so it can never touch the running
 *       isolated platform Cerbos PDP. This is the evidence/production path.</li>
 *   <li>{@link LocalPdpDecisionSource} — the in-process C3 {@link PolicyExpectationEvaluator}, which
 *       reasons over the same closed decision set the runtime PDP emits. Fully reproducible with no
 *       Docker, so the harness pins the diff behaviour deterministically. (Same belt-and-braces split
 *       C3 uses: constrained fidelity evaluator for the reproducible number, real Cerbos for
 *       evidence.)</li>
 * </ul>
 */
public interface PdpDecisionSource {

    /** A stable identifier for the PDP behind this source, recorded in the review provenance. */
    String sourceId();

    /** Whether this source can run right now (the real-Cerbos source needs Docker or a cerbos binary). */
    boolean isAvailable();

    /** Evaluate every cell against the immutable bundle and return the real per-cell decisions. */
    PdpBatchResult evaluate(BundleSnapshot bundle, List<FixtureCell> cells);
}
