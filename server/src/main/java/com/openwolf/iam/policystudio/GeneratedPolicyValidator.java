package com.openwolf.iam.policystudio;

import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * The deterministic post-generation gate (Axiom Story C2) — the second half of "the parser/
 * validator is the control". Given a typed {@link PolicyIR} and the {@link PolicyAuthoringRequest}
 * that produced it, it decides ACCEPT/REJECT over facts, never trusting the model's intent:
 *
 * <ol>
 *   <li><b>Shape</b> — Cerbos v1; the target resource kind; a tenant restriction child
 *       ({@code REQUIRE_PARENTAL_CONSENT_FOR_ALLOWS}), so it can only narrow, never edit a base.</li>
 *   <li><b>Scope containment</b> — the scope is inside the author's subtree, compared
 *       <em>segment-by-segment</em> (never string-prefix); a descendant only if subscopes enabled.</li>
 *   <li><b>Grounding</b> — every action / role / import / attribute / classification the policy
 *       names is in the manifest vocabulary.</li>
 *   <li><b>Finite + no wildcard grant</b> — no {@code "*"} action anywhere; no {@code roles: ["*"]}
 *       ALLOW.</li>
 *   <li><b>Tenant-equality backstop</b> — the base bundle it inherits from carries the equality
 *       guard (defence-in-depth against a mislabeled scope).</li>
 *   <li><b>Totality</b> — every base-ceiling {@code (action, role)} tuple has an explicit ALLOW or
 *       DENY in the child, so nothing falls through to the parent ALLOW (fail-open).</li>
 *   <li><b>Identity</b> — the {@code resource@scope} identity does not collide with a base policy.</li>
 * </ol>
 *
 * Every failed check is collected into {@link Result#violations()} (it does not short-circuit) so
 * an operator sees the full picture. A single violation means REJECT.
 */
@Component
public class GeneratedPolicyValidator {

    public static final String API_VERSION = "api.cerbos.dev/v1";
    public static final String TENANT_CHILD_POSTURE = "SCOPE_PERMISSIONS_REQUIRE_PARENTAL_CONSENT_FOR_ALLOWS";
    private static final String WILDCARD = "*";

    /** {@code R.attr.<name>} / {@code P.attr.<name>} references in a CEL condition. */
    private static final Pattern ATTR_REF = Pattern.compile("\\b[PR]\\.attr\\.([A-Za-z_][A-Za-z0-9_]*)");
    /** Double-quoted or single-quoted string literals in a CEL condition. */
    private static final Pattern STRING_LITERAL = Pattern.compile("\"([^\"]*)\"|'([^']*)'");

    public record Result(boolean accepted, List<String> violations) {
        public Result {
            violations = List.copyOf(violations);
        }
        public static Result accept() {
            return new Result(true, List.of());
        }
        public static Result reject(List<String> violations) {
            return new Result(false, violations);
        }
    }

    public Result validate(PolicyIR ir, PolicyAuthoringRequest request) {
        List<String> v = new ArrayList<>();
        ManifestVocabulary vocab = request.vocabulary();
        BaseCeiling ceiling = request.baseCeiling();

        // 1. Shape ────────────────────────────────────────────────────────────────────────────
        if (!API_VERSION.equals(ir.apiVersion())) {
            v.add("apiVersion must be '" + API_VERSION + "' (was '" + ir.apiVersion() + "')");
        }
        if (!vocab.resourceKind().equals(ir.resource())) {
            v.add("resource '" + ir.resource() + "' is not the authoring target '" + vocab.resourceKind() + "'");
        }
        if (!TENANT_CHILD_POSTURE.equals(ir.scopePermissions())) {
            v.add("a generated tenant policy must set scopePermissions=" + TENANT_CHILD_POSTURE
                    + " (a restriction child that can only narrow the base) — was '" + ir.scopePermissions() + "'");
        }

        // 2. Scope containment (segment-wise, never string-prefix) ──────────────────────────────
        TenantScope candidateScope;
        try {
            candidateScope = TenantScope.of(ir.scope());
            if (candidateScope.isRoot()) {
                v.add("a generated policy must target a tenant scope, not the root ceiling scope");
            } else if (!request.authorScope().contains(candidateScope, request.subscopesEnabled())) {
                v.add("scope '" + ir.scope() + "' escapes the author's subtree '"
                        + request.authorScope().value() + "'"
                        + (request.subscopesEnabled() ? " (descendants allowed)" : " (only the exact tenant is allowed)"));
            }
        } catch (IllegalArgumentException e) {
            v.add("invalid scope: " + e.getMessage());
        }

        // 7. Identity collision ────────────────────────────────────────────────────────────────
        if (ceiling.reservedIdentities().contains(ir.identity())) {
            v.add("policy identity '" + ir.identity() + "' collides with an existing base-bundle policy");
        }

        // 5. Tenant-equality backstop inherited from the base bundle ───────────────────────────
        if (!ceiling.carriesTenantEqualityBackstop()) {
            v.add("the base ceiling this policy inherits from does not carry the tenant-equality backstop");
        }

        // 3/4. Per-rule grounding, finiteness, no wildcard grant ───────────────────────────────
        for (int i = 0; i < ir.rules().size(); i++) {
            PolicyIR.Rule rule = ir.rules().get(i);
            String at = "rule[" + i + "]";

            if (rule.actions().isEmpty()) {
                v.add(at + " lists no actions");
            }
            for (String action : rule.actions()) {
                if (WILDCARD.equals(action)) {
                    v.add(at + " uses a wildcard action '*' — actions must be finite and enumerated");
                } else if (!vocab.actions().contains(action)) {
                    v.add(at + " action '" + action + "' is not in the manifest vocabulary");
                }
            }
            for (String role : rule.roles()) {
                if (WILDCARD.equals(role) && rule.isAllow()) {
                    v.add(at + " ALLOW grants roles:[\"*\"] — a wildcard grant is never permitted");
                } else if (!WILDCARD.equals(role) && !vocab.roles().contains(role)) {
                    v.add(at + " role '" + role + "' is not in the manifest vocabulary");
                }
            }
            for (String imp : rule.derivedRoles()) {
                if (!vocab.approvedImports().contains(imp) && !vocab.roles().contains(imp)) {
                    v.add(at + " derived role '" + imp + "' is not an approved/known role");
                }
            }
            checkConditionGrounding(rule.conditionText(), vocab, at, v);
        }

        // Imports must all be approved ─────────────────────────────────────────────────────────
        for (String imp : ir.importDerivedRoles()) {
            if (!vocab.approvedImports().contains(imp)) {
                v.add("importDerivedRoles '" + imp + "' is not an approved module");
            }
        }

        // 6. Totality over the base ceiling ────────────────────────────────────────────────────
        for (BaseCeiling.Tuple tuple : ceiling.tuples()) {
            if (!covers(ir, tuple)) {
                v.add("base-ceiling tuple (action='" + tuple.action() + "', role='" + tuple.role()
                        + "') is not covered — it would fall through to the parent ALLOW (fail-open)");
            }
        }

        return v.isEmpty() ? Result.accept() : Result.reject(v);
    }

    private void checkConditionGrounding(String condition, ManifestVocabulary vocab, String at, List<String> v) {
        if (condition == null || condition.isBlank()) {
            return;
        }
        Matcher am = ATTR_REF.matcher(condition);
        while (am.find()) {
            String attr = am.group(1);
            if (!vocab.attributes().contains(attr)) {
                v.add(at + " condition references attribute '" + attr + "' not in the manifest vocabulary");
            }
        }
        // A string literal that matches a *known* attribute domain (classification-like) must be a
        // declared classification. We only flag literals that look domain-bearing: if a literal is
        // not a classification, not a role, not an action, not a scope segment, and not a bare
        // attribute value, and it is compared against a classification attribute, it is ungrounded.
        Matcher sm = STRING_LITERAL.matcher(condition);
        while (sm.find()) {
            String lit = sm.group(1) != null ? sm.group(1) : sm.group(2);
            if (lit == null || lit.isBlank()) {
                continue;
            }
            // Only enforce classification grounding: a literal used where classifications live must
            // be declared. We recognise a classification comparison by proximity to data_classification.
            if (condition.contains("data_classification") && looksLikeClassificationLiteral(lit)
                    && !vocab.classifications().contains(lit)
                    && !vocab.actions().contains(lit)
                    && !vocab.roles().contains(lit)) {
                v.add(at + " condition uses classification literal '" + lit
                        + "' not in the manifest vocabulary");
            }
        }
    }

    /** A conservative heuristic: a lowercase, hyphen/word token (no spaces, no CEL operators). */
    private boolean looksLikeClassificationLiteral(String lit) {
        return lit.matches("[a-z][a-z0-9-]*");
    }

    /** A base tuple is covered iff some rule (ALLOW or DENY) opines on the (action, role): its
     *  actions include the action, and its roles/derivedRoles(expanded to the tuple's role) match.
     *  Mirrors {@code scripts/cerbos-tenant-totality-lint.py}. Wildcards in actions/roles are
     *  banned elsewhere, so exact matching here is intentional. */
    private boolean covers(PolicyIR ir, BaseCeiling.Tuple tuple) {
        for (PolicyIR.Rule rule : ir.rules()) {
            boolean actionMatch = rule.actions().contains(tuple.action());
            boolean roleMatch = rule.roles().contains(tuple.role()) || rule.derivedRoles().contains(tuple.role());
            if (actionMatch && roleMatch) {
                return true;
            }
        }
        return false;
    }
}
