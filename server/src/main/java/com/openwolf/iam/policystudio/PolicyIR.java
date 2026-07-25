package com.openwolf.iam.policystudio;

import java.util.List;

/**
 * The typed internal representation of a Cerbos resource policy (Axiom Story C2). The model's raw
 * text is NEVER stored or reasoned over directly — {@link PolicyYamlParser} lowers a proposal into
 * this closed shape (rejecting anything that does not fit), the validator reasons over the IR, and
 * {@link CanonicalPolicyWriter} materialises canonical YAML back from the validated IR. Storing the
 * IR-derived canonical form (not the model text) is what makes "the parser is the control" true.
 *
 * @param apiVersion        the Cerbos API version string (must be {@code api.cerbos.dev/v1})
 * @param version           the resource-policy version
 * @param resource          the resource kind
 * @param scope             the raw scope string ({@code ""} = root)
 * @param scopePermissions  the scopePermissions posture (null if unset)
 * @param importDerivedRoles imported derived-role module names (never null; empty if none)
 * @param rules             the ordered rules
 */
public record PolicyIR(
        String apiVersion,
        String version,
        String resource,
        String scope,
        String scopePermissions,
        List<String> importDerivedRoles,
        List<Rule> rules) {

    public PolicyIR {
        importDerivedRoles = importDerivedRoles == null ? List.of() : List.copyOf(importDerivedRoles);
        rules = rules == null ? List.of() : List.copyOf(rules);
    }

    /**
     * One Cerbos rule.
     *
     * <p>The condition is kept BOTH as the raw parsed node ({@code condition} — a
     * SafeConstructor-produced tree of maps/lists/scalars, so canonical YAML can be re-emitted
     * faithfully) AND as flattened CEL text ({@code conditionText()} — for the gate to scan for
     * referenced attributes / classification literals / the tenant-equality backstop; flattening
     * avoids YAML line-wrapping splitting an expression, the same reason the equality lint walks
     * string leaves).
     *
     * @param actions      the actions the rule opines on
     * @param effect       {@code EFFECT_ALLOW} or {@code EFFECT_DENY}
     * @param roles        raw principal roles ({@code "*"} preserved so the gate can reject it)
     * @param derivedRoles derived-role names
     * @param condition    the raw parsed condition node ({@code null} if none)
     */
    public record Rule(
            List<String> actions,
            String effect,
            List<String> roles,
            List<String> derivedRoles,
            Object condition) {

        public Rule {
            actions = actions == null ? List.of() : List.copyOf(actions);
            roles = roles == null ? List.of() : List.copyOf(roles);
            derivedRoles = derivedRoles == null ? List.of() : List.copyOf(derivedRoles);
        }

        public boolean isAllow() {
            return "EFFECT_ALLOW".equals(effect);
        }

        /** Every scalar string leaf under the condition, joined — enough for the gate to scan. */
        public String conditionText() {
            if (condition == null) {
                return "";
            }
            List<String> leaves = new java.util.ArrayList<>();
            collectStringLeaves(condition, leaves);
            return String.join(" ", leaves);
        }

        private static void collectStringLeaves(Object node, List<String> out) {
            switch (node) {
                case String s -> out.add(s);
                case java.util.Map<?, ?> m -> m.values().forEach(x -> collectStringLeaves(x, out));
                case List<?> l -> l.forEach(x -> collectStringLeaves(x, out));
                case null -> { }
                default -> { }
            }
        }
    }

    /** The stable {@code resource@scope} identity used for collision detection. */
    public String identity() {
        return resource + "@" + (scope == null ? "" : scope);
    }
}
