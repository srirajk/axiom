package com.openwolf.iam.policystudio;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;

/**
 * One principal×resource×action cell of the consequence-diff evaluation matrix (Axiom Story C4).
 *
 * <p>A cell is a fully-specified authorization question — the SAME shape as a C3 {@link Expectation},
 * minus the expected effect. C4 never asserts what the effect <em>should</em> be; it asks each of the
 * two immutable bundle snapshots what the effect <em>is</em> and diffs the two real answers. So a cell
 * carries no {@link Effect} and no {@link ProbeKind}-as-expectation — it is a pure input tuple.
 *
 * <p>World B: the roles, action and attribute names are drawn from the tenant's manifest vocabulary by
 * the caller ({@link ConsequenceFixtureMatrix#fromExpectationSet}) — never hardcoded here.
 *
 * @param principalRoles the principal's roles (matched against a rule's roles / derived roles)
 * @param principalTenant the tenant the principal is homed in ({@code null} in a single-tenant probe)
 * @param principalAttrs  additional {@code P.attr.*} the real-PDP renderer needs (e.g. segment map);
 *                        unused by the in-process fidelity evaluator, empty by default
 * @param resourceTenant  the tenant the resource is homed in (differs from the principal in a
 *                        cross-tenant cell)
 * @param resourceAttrs   the resource's {@code R.attr.*} attributes (classification, domain, …)
 * @param action          the action under test
 * @param label           a stable, human-readable, canonical-ordering key for this cell
 */
public record FixtureCell(
        Set<String> principalRoles,
        String principalTenant,
        Map<String, Object> principalAttrs,
        String resourceTenant,
        Map<String, Object> resourceAttrs,
        String action,
        String label) {

    public FixtureCell {
        principalRoles = Set.copyOf(principalRoles);
        principalAttrs = Map.copyOf(principalAttrs);
        resourceAttrs = Map.copyOf(resourceAttrs);
        if (action == null || action.isBlank()) {
            throw new IllegalArgumentException("action must be set");
        }
        if (label == null || label.isBlank()) {
            throw new IllegalArgumentException("label must be set");
        }
    }

    public boolean isCrossTenant() {
        return resourceTenant != null && !resourceTenant.equals(principalTenant);
    }

    /**
     * A deterministic, tenant/role/action/attr-canonical key for this cell — the unit of the
     * {@code fixtureSetHash} and the canonical delta. Sorting the roles and attrs makes the key
     * independent of set/map iteration order so the review hash is reproducible across machines.
     */
    public String canonicalKey() {
        Map<String, Object> sortedAttrs = new TreeMap<>(resourceAttrs);
        return "roles=" + new java.util.TreeSet<>(principalRoles)
                + ";pTenant=" + principalTenant
                + ";rTenant=" + resourceTenant
                + ";action=" + action
                + ";rAttrs=" + sortedAttrs;
    }

    /** Build the {@code P.attr.*} map the real-PDP renderer sends: tenant_id plus any extra attrs. */
    public Map<String, Object> effectivePrincipalAttrs() {
        Map<String, Object> m = new LinkedHashMap<>(principalAttrs);
        if (principalTenant != null && !m.containsKey("tenant_id")) {
            m.put("tenant_id", principalTenant);
        }
        return m;
    }

    /** Build the {@code R.attr.*} map the real-PDP renderer sends: resource attrs plus tenant_id. */
    public Map<String, Object> effectiveResourceAttrs() {
        Map<String, Object> m = new LinkedHashMap<>(resourceAttrs);
        if (resourceTenant != null && !m.containsKey("tenant_id")) {
            m.put("tenant_id", resourceTenant);
        }
        return m;
    }
}
