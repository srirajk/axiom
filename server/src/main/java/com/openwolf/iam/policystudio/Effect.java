package com.openwolf.iam.policystudio;

/**
 * A binary authorization decision as an oracle expectation or an evaluated policy decision
 * (Axiom Story C3). Deliberately only {@code ALLOW}/{@code DENY} — the independent test oracle and
 * the {@link PolicyExpectationEvaluator} reason over the same closed set the runtime PDP emits.
 */
public enum Effect {
    ALLOW,
    DENY
}
