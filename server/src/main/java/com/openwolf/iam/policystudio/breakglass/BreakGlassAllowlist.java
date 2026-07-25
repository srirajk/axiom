package com.openwolf.iam.policystudio.breakglass;

import java.util.Set;

/**
 * The approved break-glass action / resource allowlists (Axiom Story C6.5). Emergency access is not
 * a blank cheque: only an explicitly pre-approved (resource kind, action) surface may ever be
 * granted through the expedited path. These come from the tenant's manifest / break-glass policy
 * config — never a hardcoded domain literal in Java (World B) — and are re-checked deterministically
 * by {@link BreakGlassValidator} BEFORE compilation.
 *
 * @param resources the resource kinds break-glass may target
 * @param actions   the actions break-glass may grant
 */
public record BreakGlassAllowlist(Set<String> resources, Set<String> actions) {

    public BreakGlassAllowlist {
        resources = Set.copyOf(resources);
        actions = Set.copyOf(actions);
    }
}
