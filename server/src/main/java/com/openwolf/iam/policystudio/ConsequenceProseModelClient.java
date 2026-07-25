package com.openwolf.iam.policystudio;

/**
 * Authoring-plane seam to an LLM that <em>phrases</em> an already-computed consequence delta into
 * human display prose (Axiom Story C4).
 *
 * <p><b>The LLM is NEVER in the truth path.</b> By the time this seam is called the machine delta,
 * the over-permission alarm flag and the {@code consequenceReviewHash} are already fixed — computed
 * entirely from real PDP decisions ({@link PdpDecisionSource}). This client may only turn the
 * pre-computed, PDP-derived delta into readable sentences; it cannot add, drop, or flip a single
 * consequence. An LLM paraphrase of the <em>policy</em> is never the diff. If this client errors, the
 * review is still fully valid — the prose is simply absent (C4.1: LLM-erroring runs are still
 * correct). {@link ConsequenceReview#withProse} attaches the prose without touching the hash, so
 * display wording can never alter the signed truth (C4.6).
 *
 * <p><b>Boundary invariant (ArchUnit-enforced by {@code PolicyAuthoringBoundaryArchTest}):</b> like
 * {@link PolicyAuthoringModelClient}, this interface is authoring-plane only and structurally
 * unreachable from runtime enforcement — token verification, the Cerbos entitlement path, coverage
 * enforcement, or agent invocation.
 */
public interface ConsequenceProseModelClient {

    /**
     * Render the already-computed review's delta set into human-readable display prose. Implementations
     * receive the review whose machine delta is FINAL; they must not (and structurally cannot) change
     * it — the returned string is display text only.
     *
     * @return display prose for the review's delta set
     */
    String phrase(ConsequenceReview review);
}
