package com.openwolf.iam.policystudio;

/**
 * Which layer of the C3 draft gate first flagged a candidate (Axiom Story C3). Recorded per corpus
 * item so the catch-rate table shows not just <em>that</em> a known-bad policy was caught but
 * <em>where</em> — and, critically, which items are caught ONLY by the independent oracle
 * ({@link #ORACLE}) and would have slipped a self-consistent, co-generated test suite (the moat).
 */
public enum CatchLayer {
    /** C2's deterministic parser/validator gate (vocabulary, scope, totality, wildcard, backstop). */
    VALIDATOR,
    /** C3's independent oracle + injected negative probes — the layer the moat adds. */
    ORACLE,
    /** The pinned Cerbos compile over the base bundle (which embeds the hand-owned B3 invariants). */
    COMPILE,
    /** No layer caught it — a published MISS. */
    UNCAUGHT
}
