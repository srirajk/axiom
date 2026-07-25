package com.openwolf.iam.auth;

import java.util.regex.Pattern;

/**
 * Tenant-binding rules for every issued token (Axiom story A1).
 *
 * <p>Two invariants live here so no token path can bypass them:
 * <ol>
 *   <li><b>tenant_id is mandatory and non-defaultable.</b> A principal whose home tenant is
 *       null/blank is <em>un-mintable</em> — {@link #requireTenant(String)} throws rather than
 *       substituting a configured default. (The seeder gives every real principal a concrete
 *       {@code tenant_id}, so this only bites a genuinely-unbound principal.)</li>
 * </ol>
 *
 * <p>Tenant ids obey the canonical grammar {@code [a-z0-9][a-z0-9-]{0,62}} — validated here so a
 * malformed tenant can never be minted into a claim or an audience.
 */
public final class TenantClaims {

    /** Canonical tenant-id grammar: lower alphanumeric start, then alphanumeric/hyphen, ≤63 chars. */
    public static final Pattern CANONICAL_TENANT_ID = Pattern.compile("[a-z0-9][a-z0-9-]{0,62}");

    private TenantClaims() {}

    /**
     * Returns the tenant id if present and canonical; otherwise throws. There is <b>no</b> default
     * substitution — a null/blank tenant means the principal is un-mintable.
     *
     * @throws IllegalStateException    if {@code tenantId} is null or blank (un-mintable principal)
     * @throws IllegalArgumentException if {@code tenantId} violates the canonical grammar
     */
    public static String requireTenant(String tenantId) {
        if (tenantId == null || tenantId.isBlank()) {
            throw new IllegalStateException(
                    "tenant_id is mandatory and has no default — this principal is un-mintable");
        }
        if (!CANONICAL_TENANT_ID.matcher(tenantId).matches()) {
            throw new IllegalArgumentException(
                    "tenant_id '" + tenantId + "' violates canonical grammar [a-z0-9][a-z0-9-]{0,62}");
        }
        return tenantId;
    }

}
