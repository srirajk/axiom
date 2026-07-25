package com.openwolf.iam.policystudio.lifecycle;

/**
 * Probes a candidate bundle before it can be activated (Axiom Story C5): stage the exact candidate
 * alongside the live versions, {@code cerbos compile}, load, and probe every invariant with
 * {@code policyVersion = candidate bundleId}. A probe failure aborts the promotion and leaves the
 * candidate INACTIVE. Behind a port so the harness can drive the version-stamping/structural invariants
 * deterministically without Docker, while the evidence path uses the pinned Cerbos.
 */
public interface CandidateProbe {

    /**
     * @throws RuntimeException if any invariant fails (the candidate must not be activated)
     */
    void verify(PolicyBundle candidate);
}
