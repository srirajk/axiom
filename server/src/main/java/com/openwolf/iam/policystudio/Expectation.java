package com.openwolf.iam.policystudio;

import java.util.Map;
import java.util.Set;

/**
 * One row of an independently-generated test oracle (Axiom Story C3): a fully-specified
 * principal/resource/action tuple together with the effect the <em>author's intent</em> requires.
 *
 * <p>Crucially, an {@code Expectation} is produced from the natural-language intent + manifest
 * vocabulary alone (via {@link TestScenarioModelClient}) and then mechanically fanned out into
 * negative probes ({@link NegativeProbeInjector}). It never derives from, and structurally cannot
 * see, the candidate policy YAML — that is the whole point of the moat. The candidate is only ever
 * consulted at <em>evaluation</em> time by {@link PolicyExpectationEvaluator}.
 *
 * @param principalRoles the principal's roles (matched against a rule's roles / derived roles)
 * @param principalTenant the tenant the principal is homed in
 * @param resourceTenant  the tenant the resource is homed in (differs from the principal only in a
 *                        {@link ProbeKind#CROSS_TENANT} probe)
 * @param resourceAttrs   the resource's non-tenant attributes (e.g. a data classification); a
 *                        {@link ProbeKind#MISSING_ATTRIBUTE} probe deliberately omits a guard attr
 * @param action          the action under test
 * @param expected        the effect the intent requires (POSITIVE ⇒ ALLOW; every probe ⇒ DENY)
 * @param kind            the provenance of this expectation
 * @param label           a stable, human-readable label used in the rendered {@code _test.yaml}
 */
public record Expectation(
        Set<String> principalRoles,
        String principalTenant,
        String resourceTenant,
        Map<String, Object> resourceAttrs,
        String action,
        Effect expected,
        ProbeKind kind,
        String label) {

    public Expectation {
        principalRoles = Set.copyOf(principalRoles);
        resourceAttrs = Map.copyOf(resourceAttrs);
        if (action == null || action.isBlank()) {
            throw new IllegalArgumentException("action must be set");
        }
        if (expected == null || kind == null) {
            throw new IllegalArgumentException("expected effect and probe kind must be set");
        }
    }

    public boolean isCrossTenant() {
        return resourceTenant != null && !resourceTenant.equals(principalTenant);
    }
}
