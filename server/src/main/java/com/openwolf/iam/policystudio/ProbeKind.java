package com.openwolf.iam.policystudio;

/**
 * The provenance of one {@link Expectation} in an independently-generated test set (Axiom Story C3).
 *
 * <p>{@link #POSITIVE} expectations come straight from the intent oracle — an ALLOW the natural-
 * language intent implies. Every other kind is a <em>mechanically injected negative probe</em>: for
 * each POSITIVE allow the {@link NegativeProbeInjector} derives one probe of each remaining kind,
 * all expected to DENY. These probes are what a self-consistent, co-generated test suite would never
 * contain — they are derived from the author's intent, not from the candidate policy's behaviour.
 */
public enum ProbeKind {
    /** The intent-implied ALLOW (or an intent-implied explicit DENY restriction). */
    POSITIVE,
    /** Same principal/action, but the resource is homed in a different tenant — must DENY. */
    CROSS_TENANT,
    /** Same principal/action, but a data-classification/segment the intent did not sanction — must DENY. */
    WRONG_SEGMENT,
    /** Same principal/action, but a guard attribute is absent — must DENY (fail-closed, never fail-open). */
    MISSING_ATTRIBUTE
}
