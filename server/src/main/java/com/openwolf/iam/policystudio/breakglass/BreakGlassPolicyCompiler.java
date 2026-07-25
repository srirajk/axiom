package com.openwolf.iam.policystudio.breakglass;

import com.openwolf.iam.policystudio.BaseCeiling;
import com.openwolf.iam.policystudio.GeneratedPolicyValidator;
import com.openwolf.iam.policystudio.PolicyIR;
import org.springframework.stereotype.Component;

import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.TreeSet;

/**
 * Lowers a bounds-validated {@link BreakGlassGrant} into a typed {@link PolicyIR} — a tenant-scoped
 * Cerbos restriction child (Axiom Story C6) that still passes the C2 {@link GeneratedPolicyValidator}
 * unchanged (shape, segment-wise scope containment, grounding, no-wildcard, totality).
 *
 * <p><b>The self-limiting idiom (the whole point):</b> the granted {@code (action, role)} tuple is
 * expressed as a COMPLEMENTARY PAIR of time-conditioned rules on the SAME tuple —
 * <pre>
 *   ALLOW  action  role   when  now() &gt;= timestamp("&lt;issuedAt&gt;") &amp;&amp; now() &lt; timestamp("&lt;expiresAt&gt;")
 *   DENY   action  role   when  now() &lt;  timestamp("&lt;issuedAt&gt;") || now() &gt;= timestamp("&lt;expiresAt&gt;")
 * </pre>
 * The ALLOW carries BOTH bounds (H1): the LOWER bound {@code now() >= timestamp(issuedAt)} makes a
 * future-dated grant inert in the PDP (it cannot fire until {@code issuedAt}), matching the bounds
 * gate's server-clock rejection.
 * A lone conditional ALLOW would be UNSAFE under {@code REQUIRE_PARENTAL_CONSENT_FOR_ALLOWS}: once
 * its condition lapses the rule becomes silence, and silence inherits the parent ALLOW (the proven
 * fall-through trap — {@code infra/cerbos/templates/tenant-deny-all.yaml}). The complementary DENY
 * makes expiry fail CLOSED: after {@code expiresAt} the explicit DENY fires (and DENY beats ALLOW in
 * Cerbos), so the grant expires <em>inside the PDP</em> with no external revocation.
 *
 * <p><b>S4 — MERGE, not replace (the fix).</b> A break-glass child must be the tenant's CURRENT active
 * grants PLUS the one time-boxed emergency tuple — never a standalone policy that DENIES every other
 * tuple. The old deny-all-else baseline was correct for totality but, once promoted into the serving
 * PDP (S1), would have <em>revoked the tenant's normal access</em> for the life of the grant. The merge
 * takes the tenant's current restriction child ({@code currentChild}; {@code null} = the tenant purely
 * inherits the base ceiling) and, for every ceiling {@code (action, role)} tuple EXCEPT the granted
 * tuple, copies the current rules byte-for-semantics, including their CEL condition trees. Rules that also
 * cover the granted tuple are split: their non-granted combinations remain unchanged and the exact tuple
 * is active only outside the new grant window. This lets the emergency ALLOW override the old decision
 * while it is live and restores the complete previous decision afterwards. It is also safe for sequential
 * break-glass grants: the earlier grant's time conditions remain nested and intact rather than becoming an
 * unconditional permanent grant.
 */
@Component
public class BreakGlassPolicyCompiler {

    /** Build the CEL predicate for {@code now() < timestamp(expiresAt)} (seconds precision, RFC3339). */
    static String beforeExpiry(BreakGlassGrant grant) {
        return "now() < timestamp(\"" + isoSeconds(grant.expiresAt()) + "\")";
    }

    /** Build the CEL predicate for {@code now() >= timestamp(expiresAt)} — the upper self-limit. */
    static String afterExpiry(BreakGlassGrant grant) {
        return "now() >= timestamp(\"" + isoSeconds(grant.expiresAt()) + "\")";
    }

    /** Build the CEL predicate for {@code now() >= timestamp(issuedAt)} — the LOWER bound (H1). */
    static String afterIssued(BreakGlassGrant grant) {
        return "now() >= timestamp(\"" + isoSeconds(grant.issuedAt()) + "\")";
    }

    /** Build the CEL predicate for {@code now() < timestamp(issuedAt)} — before the grant is live. */
    static String beforeIssued(BreakGlassGrant grant) {
        return "now() < timestamp(\"" + isoSeconds(grant.issuedAt()) + "\")";
    }

    /**
     * The ALLOW window: live ONLY inside {@code [issuedAt, expiresAt)}. Carries BOTH bounds so a
     * future-dated grant is inert in the PDP (the lower bound fails until {@code issuedAt}) exactly as
     * it is rejected by the bounds gate (H1).
     */
    static String activeWindow(BreakGlassGrant grant) {
        return afterIssued(grant) + " && " + beforeExpiry(grant);
    }

    /** The complementary DENY: fires whenever now() is OUTSIDE {@code [issuedAt, expiresAt)}. */
    static String outsideWindow(BreakGlassGrant grant) {
        return beforeIssued(grant) + " || " + afterExpiry(grant);
    }

    private static String isoSeconds(java.time.Instant instant) {
        return instant.truncatedTo(ChronoUnit.SECONDS).toString();
    }

    private static Object matchCondition(String expr) {
        return Map.of("match", Map.of("expr", expr));
    }

    /**
     * Compile the grant against the tenant's inherited base ceiling ({@code currentChild = null}) — the
     * tenant has no restriction child yet, so every ceiling tuple is preserved (ALLOWed) and only the
     * granted tuple is time-boxed. Convenience overload used by the C6 authoring/bounds harness.
     */
    public PolicyIR compile(BreakGlassGrant grant, BaseCeiling ceiling) {
        return compile(grant, ceiling, null);
    }

    /**
     * Compile the grant into a tenant restriction child that MERGES the temporary emergency tuple with the
     * tenant's CURRENT active grants (S4). The caller runs the produced IR through the C2
     * {@link GeneratedPolicyValidator} to confirm admissibility (see {@code BreakGlassAuthoringService}).
     *
     * @param grant        the bounds-validated emergency grant
     * @param ceiling      the immutable base ceiling (the totality target)
     * @param currentChild the tenant's current active restriction child ({@code null} = inherits the base
     *                     ceiling directly); its per-tuple effects are preserved, so normal access survives
     */
    public PolicyIR compile(BreakGlassGrant grant, BaseCeiling ceiling, PolicyIR currentChild) {
        List<PolicyIR.Rule> rules = new ArrayList<>();

        // ── The break-glass grant: a complementary time-conditioned ALLOW/DENY on the granted tuple.
        //    Emitted FIRST so the granted tuple is governed solely by the time pair (and so a scan for the
        //    emergency ALLOW/DENY finds the time-conditioned rule, not a merged baseline rule). ──
        rules.add(new PolicyIR.Rule(
                List.of(grant.action()), "EFFECT_ALLOW", List.of(grant.role()), List.of(),
                matchCondition(activeWindow(grant))));

        if (currentChild == null) {
            // No restriction child existed: preserve inherited base ALLOWs for every other ceiling tuple,
            // while the granted tuple gets the explicit outside-window DENY needed to self-limit.
            rules.add(new PolicyIR.Rule(
                    List.of(grant.action()), "EFFECT_DENY", List.of(grant.role()), List.of(),
                    matchCondition(outsideWindow(grant))));
            appendInheritedBaseline(rules, grant, ceiling);
        } else {
            appendConditionPreservingMerge(rules, grant, currentChild);
        }

        return new PolicyIR(
                GeneratedPolicyValidator.API_VERSION,
                "default",
                grant.resourceKind(),
                grant.scope().value(),
                GeneratedPolicyValidator.TENANT_CHILD_POSTURE,
                currentChild == null ? List.of() : currentChild.importDerivedRoles(),
                rules);
    }

    private static void appendInheritedBaseline(List<PolicyIR.Rule> rules,
                                                BreakGlassGrant grant,
                                                BaseCeiling ceiling) {
        Map<String, TreeSet<String>> allowByRole = new TreeMap<>();
        for (BaseCeiling.Tuple tuple : ceiling.tuples()) {
            if (!isGrantedTuple(grant, tuple.action(), tuple.role())) {
                allowByRole.computeIfAbsent(tuple.role(), ignored -> new TreeSet<>()).add(tuple.action());
            }
        }
        allowByRole.forEach((role, actions) -> rules.add(new PolicyIR.Rule(
                List.copyOf(actions), "EFFECT_ALLOW", List.of(role), List.of(), null)));
    }

    /** Copy every current rule, splitting only the exact granted action/role cross-product. */
    private static void appendConditionPreservingMerge(List<PolicyIR.Rule> out,
                                                       BreakGlassGrant grant,
                                                       PolicyIR currentChild) {
        List<Object> previousConditionalMatches = new ArrayList<>();
        boolean previousUnconditionalMatch = false;

        for (PolicyIR.Rule rule : currentChild.rules()) {
            boolean actionMatch = rule.actions().contains(grant.action());
            if (actionMatch && !rule.derivedRoles().isEmpty()) {
                // The child IR carries derived-role names, while the ceiling/grant carries expanded parent
                // roles. Without the exact module expansion here we cannot prove whether this rule also
                // governs the granted tuple, so copying or splitting it could leave a DENY active during the
                // emergency window or silently widen a conditional ALLOW. Reject instead of guessing.
                throw new IllegalArgumentException("cannot safely merge break-glass action '"
                        + grant.action() + "' while current policy rule uses derivedRoles "
                        + rule.derivedRoles() + "; trusted parent-role expansion is required");
            }
            boolean rawRoleMatch = rule.roles().contains(grant.role());
            if (!actionMatch || !rawRoleMatch) {
                out.add(rule);
                continue;
            }

            // Preserve all other actions with all original identities and the untouched condition.
            List<String> otherActions = without(rule.actions(), grant.action());
            if (!otherActions.isEmpty()) {
                out.add(new PolicyIR.Rule(otherActions, rule.effect(), rule.roles(), rule.derivedRoles(),
                        rule.condition()));
            }

            // Preserve this action for every other role/derived-role, also untouched.
            List<String> otherRoles = without(rule.roles(), grant.role());
            List<String> otherDerivedRoles = rule.derivedRoles();
            if (!otherRoles.isEmpty() || !otherDerivedRoles.isEmpty()) {
                out.add(new PolicyIR.Rule(List.of(grant.action()), rule.effect(), otherRoles,
                        otherDerivedRoles, rule.condition()));
            }

            // Restore the old exact-tuple decision outside the new emergency window. Keeping the raw
            // match subtree inside an `all` retains expr/all/any/none semantics without flattening CEL.
            List<String> exactRoles = rawRoleMatch ? List.of(grant.role()) : List.of();
            out.add(new PolicyIR.Rule(List.of(grant.action()), rule.effect(), exactRoles, List.of(),
                    andWithExpression(rule.condition(), outsideWindow(grant))));

            if (rule.condition() == null) {
                previousUnconditionalMatch = true;
            } else {
                previousConditionalMatches.add(matchNode(rule.condition()));
            }
        }

        // If the old policy was silent when none of its conditional rules matched, make that case an
        // explicit DENY outside the emergency window. This prevents parental-consent fall-through without
        // overriding any old conditional ALLOW/DENY that actually matched.
        if (!previousUnconditionalMatch) {
            Object condition = previousConditionalMatches.isEmpty()
                    ? matchCondition(outsideWindow(grant))
                    : outsideAndNoneOf(outsideWindow(grant), previousConditionalMatches);
            out.add(new PolicyIR.Rule(List.of(grant.action()), "EFFECT_DENY", List.of(grant.role()),
                    List.of(), condition));
        }
    }

    private static boolean isGrantedTuple(BreakGlassGrant grant, String action, String role) {
        return grant.action().equals(action) && grant.role().equals(role);
    }

    private static List<String> without(List<String> values, String excluded) {
        return values.stream().filter(value -> !excluded.equals(value)).toList();
    }

    private static Object andWithExpression(Object condition, String expression) {
        if (condition == null) {
            return matchCondition(expression);
        }
        Map<String, Object> all = new LinkedHashMap<>();
        all.put("of", List.of(matchNode(condition), Map.of("expr", expression)));
        return Map.of("match", Map.of("all", all));
    }

    private static Object outsideAndNoneOf(String outsideExpression, List<Object> previousMatches) {
        Map<String, Object> none = new LinkedHashMap<>();
        none.put("of", List.copyOf(previousMatches));
        Map<String, Object> all = new LinkedHashMap<>();
        all.put("of", List.of(Map.of("expr", outsideExpression), Map.of("none", none)));
        return Map.of("match", Map.of("all", all));
    }

    private static Object matchNode(Object condition) {
        if (!(condition instanceof Map<?, ?> conditionMap) || !conditionMap.containsKey("match")) {
            throw new IllegalArgumentException("cannot safely merge a policy rule whose condition has no match node");
        }
        Object match = conditionMap.get("match");
        if (!(match instanceof Map<?, ?>)) {
            throw new IllegalArgumentException("cannot safely merge a policy rule with a non-object match node");
        }
        return match;
    }
}
