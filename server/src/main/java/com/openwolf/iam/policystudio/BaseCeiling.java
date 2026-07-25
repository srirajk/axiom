package com.openwolf.iam.policystudio;

import java.util.Set;

/**
 * The immutable base-ceiling contract a generated tenant policy is checked against (Axiom Story
 * C2.4 totality). The base (root, {@code scope: ""}) resource policy is the CEILING every tenant
 * narrows from; under {@code SCOPE_PERMISSIONS_REQUIRE_PARENTAL_CONSENT_FOR_ALLOWS} a tenant child
 * that is <em>silent</em> on a base-allowed tuple does not deny it — the tuple falls through and
 * inherits the base ALLOW (fail-open). So an accepted candidate MUST have an explicit opinion
 * (ALLOW or DENY) on every base tuple. This record carries the ceiling to check totality against.
 *
 * @param resourceKind                the resource kind the ceiling is for
 * @param tuples                      every base-allowed {@code (action, role)} tuple, with derived
 *                                    roles already expanded to their parent roles (mirrors
 *                                    {@code scripts/cerbos-tenant-totality-lint.py})
 * @param carriesTenantEqualityBackstop whether the base policy imports a derived-role module whose
 *                                    condition carries {@code P.attr.tenant_id == R.attr.tenant_id}
 *                                    — the backstop the child inherits under parental consent
 * @param reservedIdentities          {@code resource@scope} identities already present in the base
 *                                    bundle; a candidate colliding with one is rejected
 */
public record BaseCeiling(
        String resourceKind,
        Set<Tuple> tuples,
        boolean carriesTenantEqualityBackstop,
        Set<String> reservedIdentities) {

    public BaseCeiling {
        if (resourceKind == null || resourceKind.isBlank()) {
            throw new IllegalArgumentException("resourceKind must be set");
        }
        tuples = Set.copyOf(tuples);
        reservedIdentities = Set.copyOf(reservedIdentities);
    }

    /** A single base-allowed {@code (action, role)} tuple. */
    public record Tuple(String action, String role) {
        public Tuple {
            if (action == null || role == null) {
                throw new IllegalArgumentException("action and role must be set");
            }
        }
    }
}
