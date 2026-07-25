package com.openwolf.iam.policystudio.lifecycle;

import java.util.List;

/**
 * A candidate bundle failed the deterministic {@link com.openwolf.iam.policystudio.GeneratedPolicyValidator}
 * re-run at promotion time (Axiom H2): a wildcard grant, a scope that escapes the author's subtree, an
 * omitted base-ceiling tuple, or an out-of-vocabulary reference. Promotion re-validates UNCONDITIONALLY —
 * it never trusts that the candidate was validated once at authoring time — so a candidate that was
 * mutated or authored past the gate is rejected here and stays INACTIVE.
 */
public class PolicyRevalidationException extends RuntimeException {

    private final List<String> violations;

    public PolicyRevalidationException(String bundleId, List<String> violations) {
        super("candidate bundle '" + bundleId + "' failed promotion re-validation ("
                + violations.size() + " violation(s)): " + String.join("; ", violations));
        this.violations = List.copyOf(violations);
    }

    public List<String> violations() {
        return violations;
    }
}
