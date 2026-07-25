package com.openwolf.iam.policystudio;

/**
 * The direction of a single {@link ConsequenceDelta} — the consequence-diff surface (Axiom Story C4).
 *
 * <p>Only two directions exist because a cell whose decision is unchanged is <em>not</em> a delta and
 * never enters the review. A {@link #WIDENED} cell (DENY&nbsp;→&nbsp;ALLOW) is the loud
 * <b>over-permission alarm</b>: access that did not exist under the current bundle would exist under
 * the candidate. A {@link #NARROWED} cell (ALLOW&nbsp;→&nbsp;DENY) is access that would be removed.
 */
public enum DeltaDirection {
    /** DENY → ALLOW: the candidate GRANTS access the current bundle denied — the over-permission alarm. */
    WIDENED,
    /** ALLOW → DENY: the candidate REMOVES access the current bundle granted. */
    NARROWED
}
