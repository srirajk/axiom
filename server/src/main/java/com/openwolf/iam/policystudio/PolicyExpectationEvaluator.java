package com.openwolf.iam.policystudio;

import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Decides what a candidate {@link PolicyIR} would return for one {@link Expectation} (Axiom Story
 * C3), so the independently-generated oracle can be run against a draft in-process — reproducibly,
 * without requiring a live Cerbos for the catch-rate harness (the real {@link CerbosCompileGate} is
 * the belt-and-braces layer when Docker is present).
 *
 * <p><b>Fidelity, honestly scoped.</b> This is NOT a general Cerbos re-implementation. It faithfully
 * models exactly the constructs the generated tenant-restriction-child shape uses:
 * <ul>
 *   <li>rule matching by {@code action ∈ rule.actions} and {@code role ∈ rule.roles ∪ derivedRoles};</li>
 *   <li>DENY-overrides-ALLOW within the child, then explicit ALLOW, then fall-through to the base
 *       ceiling (the parent ALLOW that a silent child inherits under parental consent);</li>
 *   <li>per-rule conditions via {@link ConditionEvaluator} (a tight CEL subset), including the
 *       fail-closed missing-attribute semantics;</li>
 *   <li>the inherited tenant-equality backstop: under {@code REQUIRE_PARENTAL_CONSENT_FOR_ALLOWS} a
 *       proper tenant child inherits the base's cross-tenant DENY, so a cross-tenant probe is DENY
 *       <em>unless</em> the candidate has broken that structure (root scope, wrong posture, or a base
 *       without the backstop) — in which case the grant leaks and the probe catches it.</li>
 * </ul>
 * It does not model beyond-ceiling child grants (parental consent already neutralises those, so no
 * corpus item depends on them). When a rule's condition falls outside the supported subset the
 * evaluator throws {@link IndeterminateException} rather than guess — the harness then records the
 * item as not oracle-decidable instead of claiming a catch.
 */
@Component
public class PolicyExpectationEvaluator {

    /** Thrown when a matching rule's condition cannot be decided and could change the outcome. */
    public static class IndeterminateException extends RuntimeException {
        public IndeterminateException(String message) {
            super(message);
        }
    }

    private final ConditionEvaluator conditions;

    public PolicyExpectationEvaluator(ConditionEvaluator conditions) {
        this.conditions = conditions;
    }

    public Effect evaluate(PolicyIR ir, BaseCeiling ceiling, Expectation e) {
        Map<String, Object> env = buildEnv(e);
        boolean anyAllow = false;
        boolean anyDeny = false;
        boolean indeterminate = false;

        for (PolicyIR.Rule rule : ir.rules()) {
            if (!rule.actions().contains(e.action())) {
                continue;
            }
            if (!roleMatches(e.principalRoles(), rule)) {
                continue;
            }
            Boolean cond = evalCondition(rule.condition(), env);
            if (cond == null) {
                indeterminate = true;
                continue;
            }
            if (!cond) {
                continue; // condition false → rule does not match
            }
            if (rule.isAllow()) {
                anyAllow = true;
            } else {
                anyDeny = true;
            }
        }

        if (anyDeny) {
            return Effect.DENY;
        }
        if (anyAllow) {
            return applyCrossTenantBackstop(ir, ceiling, e);
        }
        if (ceilingAllows(ceiling, e)) {
            return applyCrossTenantBackstop(ir, ceiling, e);
        }
        if (indeterminate) {
            throw new IndeterminateException(
                    "a matching rule's condition is outside the supported subset and could allow: " + e.label());
        }
        return Effect.DENY;
    }

    private Effect applyCrossTenantBackstop(PolicyIR ir, BaseCeiling ceiling, Expectation e) {
        if (e.kind() != ProbeKind.CROSS_TENANT) {
            return Effect.ALLOW;
        }
        boolean parentalConsent = GeneratedPolicyValidator.TENANT_CHILD_POSTURE.equals(ir.scopePermissions());
        boolean properChild = !isRootScope(ir.scope());
        if (ceiling.carriesTenantEqualityBackstop() && parentalConsent && properChild) {
            return Effect.DENY; // inherited backstop denies cross-tenant
        }
        return Effect.ALLOW; // structure broken → the grant leaks across tenants
    }

    private static boolean isRootScope(String scope) {
        return scope == null || scope.isBlank();
    }

    private static boolean roleMatches(Set<String> principalRoles, PolicyIR.Rule rule) {
        for (String r : principalRoles) {
            if (rule.roles().contains(r) || rule.derivedRoles().contains(r)) {
                return true;
            }
        }
        return false;
    }

    private boolean ceilingAllows(BaseCeiling ceiling, Expectation e) {
        for (BaseCeiling.Tuple t : ceiling.tuples()) {
            if (t.action().equals(e.action()) && e.principalRoles().contains(t.role())) {
                return true;
            }
        }
        return false;
    }

    private Map<String, Object> buildEnv(Expectation e) {
        Map<String, Object> env = new LinkedHashMap<>();
        if (e.principalTenant() != null) {
            env.put("P.attr.tenant_id", e.principalTenant());
        }
        if (e.resourceTenant() != null) {
            env.put("R.attr.tenant_id", e.resourceTenant());
        }
        for (Map.Entry<String, Object> a : e.resourceAttrs().entrySet()) {
            env.put("R.attr." + a.getKey(), a.getValue());
        }
        return env;
    }

    /** @return TRUE/FALSE if decidable, {@code null} if the condition is outside the supported subset. */
    private Boolean evalCondition(Object conditionNode, Map<String, Object> env) {
        if (conditionNode == null) {
            return Boolean.TRUE; // unconditional rule
        }
        List<String> exprs = extractExprs(conditionNode);
        if (exprs.isEmpty()) {
            return null; // a condition shape we do not model (e.g. match.all/any tree) → indeterminate
        }
        boolean result = true;
        for (String expr : exprs) {
            try {
                result = result && conditions.evaluate(expr, env);
            } catch (ConditionEvaluator.ConditionErrorException missing) {
                return Boolean.FALSE; // missing attribute in a comparison → rule non-match (fail-closed)
            } catch (ConditionEvaluator.UnsupportedConditionException unsupported) {
                return null; // outside the subset → indeterminate
            }
        }
        return result;
    }

    /** Recursively collect every {@code expr:} string value from a raw parsed condition node. */
    private List<String> extractExprs(Object node) {
        List<String> out = new ArrayList<>();
        collectExprs(node, out);
        return out;
    }

    private void collectExprs(Object node, List<String> out) {
        switch (node) {
            case Map<?, ?> m -> {
                for (Map.Entry<?, ?> entry : m.entrySet()) {
                    if ("expr".equals(entry.getKey()) && entry.getValue() instanceof String s) {
                        out.add(s);
                    } else {
                        collectExprs(entry.getValue(), out);
                    }
                }
            }
            case List<?> l -> l.forEach(x -> collectExprs(x, out));
            default -> { }
        }
    }
}
