package com.openwolf.iam.policystudio.breakglass;

import com.openwolf.iam.policystudio.GeneratedPolicyValidator;
import com.openwolf.iam.policystudio.PolicyIR;

/**
 * The compiled + doubly-gated break-glass artifact (Axiom Story C6). Carries the typed IR, its
 * canonical YAML (what would be promoted/compiled into the bundle), and BOTH gate results: the C6
 * bounds gate ({@link BreakGlassValidator}) and the C2 deterministic policy gate
 * ({@link GeneratedPolicyValidator}). It is admissible for two-person approval only when BOTH gates
 * accepted — a cross-tenant scope, a too-long TTL, a wildcard, or a malformed expiry leaves it
 * inadmissible with the exact violations recorded.
 */
public record BreakGlassArtifact(
        BreakGlassGrant grant,
        PolicyIR ir,
        String canonicalYaml,
        BreakGlassValidator.Result boundsResult,
        GeneratedPolicyValidator.Result c2Result) {

    /** True iff BOTH the C6 bounds gate and the C2 policy gate accepted the artifact. */
    public boolean admissible() {
        return boundsResult.accepted() && c2Result.accepted();
    }
}
