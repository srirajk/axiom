package com.openwolf.iam.policystudio;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * The Axiom Story C3 harness fixtures — the hand-reviewed known-bad corpus + the seeded, deterministic
 * intent oracle. NO real LLM is involved: the oracle replays a per-intent {@link IntentSpec} that was
 * authored FROM THE INTENT (never from the paired bad YAML), which is exactly the moat under test.
 *
 * <p>The corpus is the headline artifact: ≥30 (intent, known-bad-policy) pairs across the seven bad-
 * policy classes the story calls out — cross-tenant grants, wrong role/segment, omitted conditions,
 * wildcard action/resource, missing-attribute fail-open, incomplete child restriction / fall-through,
 * and scope-boundary confusion. Each item records the layer expected to catch it so a future change
 * that lets one slip turns {@link KnownBadCorpusCatchRateTest} red (the "no regression" guarantee).
 */
final class C3TestGenFixtures {

    private C3TestGenFixtures() {}

    static final String CHAT_USER = "chat_user";
    static final String RELATIONSHIP_MANAGER = "relationship_manager";
    static final String PLATFORM_ADMIN = "platform_admin";
    static final String DOMAIN_ADMIN = "domain_admin";

    static final String CAT_CROSS_TENANT = "cross_tenant";
    static final String CAT_WILDCARD = "wildcard";
    static final String CAT_WRONG_ROLE_SEGMENT = "wrong_role_segment";
    static final String CAT_OMITTED_CONDITION = "omitted_condition";
    static final String CAT_MISSING_ATTRIBUTE = "missing_attribute_failopen";
    static final String CAT_INCOMPLETE_FALLTHROUGH = "incomplete_fallthrough";
    static final String CAT_SCOPE_BOUNDARY = "scope_boundary";

    /** The manifest-grounded probe attributes (World B: names come from the manifest, not hardcoded here). */
    static ProbeAttributes probeAttributes() {
        return new ProbeAttributes("tenant_id", "data_classification");
    }

    // ── the seeded intent oracle (the stubbed model client) ───────────────────────────────────

    /** An intent-implied decision. ALLOW grants are fanned into negative probes; DENY grants are
     *  intent-declared restrictions that a lazy policy tends to leave over-permissive. */
    record Grant(Set<String> roles, String action, String classification, Effect effect) {}

    /** The full set of decisions one natural-language intent implies (authored from the intent alone). */
    record IntentSpec(List<Grant> grants) {}

    static Grant allow(Set<String> roles, String action, String classification) {
        return new Grant(roles, action, classification, Effect.ALLOW);
    }

    static Grant deny(Set<String> roles, String action) {
        return new Grant(roles, action, null, Effect.DENY);
    }

    static IntentSpec spec(Grant... grants) {
        return new IntentSpec(List.of(grants));
    }

    /**
     * The deterministic oracle: from a {@link TestScenarioRequest} (intent + vocabulary — NO YAML), it
     * replays the intent's {@link IntentSpec} into a positive {@link TestExpectationSet}. It never sees,
     * and cannot reach, the candidate policy.
     */
    static final class SeededIntentOracle implements TestScenarioModelClient {
        private final Map<String, IntentSpec> byIntent;

        SeededIntentOracle(Map<String, IntentSpec> byIntent) {
            this.byIntent = Map.copyOf(byIntent);
        }

        @Override
        public TestExpectationSet proposeExpectations(TestScenarioRequest request) {
            IntentSpec s = byIntent.get(request.intent());
            if (s == null) {
                throw new IllegalStateException("no seeded intent spec for: " + request.intent());
            }
            String tenant = request.authorScope().isRoot() ? "root" : request.authorScope().value();
            List<Expectation> out = new java.util.ArrayList<>();
            int i = 0;
            for (Grant g : s.grants()) {
                Map<String, Object> attrs = new LinkedHashMap<>();
                if (g.classification() != null) {
                    attrs.put("data_classification", g.classification());
                }
                String verb = g.effect() == Effect.ALLOW ? "allow" : "deny";
                out.add(new Expectation(
                        g.roles(), tenant, tenant, attrs, g.action(), g.effect(),
                        ProbeKind.POSITIVE,
                        "intent_" + verb + "_" + String.join("+", g.roles()) + "_" + g.action() + "_" + (i++)));
            }
            return TestExpectationSet.of(out);
        }
    }

    // ── requests (authoring context handed to BOTH the generator and, projected, the oracle) ────

    static PolicyAuthoringRequest acmeRequest(String intent) {
        return new PolicyAuthoringRequest(intent, PolicyStudioFixtures.agentVocab(),
                TenantScope.of("acme"), false, PolicyStudioFixtures.agentCeiling());
    }

    static PolicyAuthoringRequest acmeRequestNoBackstop(String intent) {
        BaseCeiling noBackstop = new BaseCeiling("agent",
                PolicyStudioFixtures.agentCeiling().tuples(), false, Set.of("agent@"));
        return new PolicyAuthoringRequest(intent, PolicyStudioFixtures.agentVocab(),
                TenantScope.of("acme"), false, noBackstop);
    }

    /** Author homed at {@code acme.a} (subscopes disabled) — for the scope-boundary confusion class. */
    static PolicyAuthoringRequest acmeSubRequest(String intent) {
        return new PolicyAuthoringRequest(intent, PolicyStudioFixtures.agentVocab(),
                TenantScope.of("acme.a"), false, PolicyStudioFixtures.agentCeiling());
    }

    // ── bad-policy YAML builders ────────────────────────────────────────────────────────────────

    /** The golden, C2-valid tenant restriction body — over-permissive relative to a narrowing intent. */
    static String compliant(String scope) {
        return PolicyStudioFixtures.candidateWithScope(scope);
    }

    static String postureOverrideParent() {
        return """
                apiVersion: api.cerbos.dev/v1
                resourcePolicy:
                  version: "default"
                  resource: agent
                  scope: "acme"
                  scopePermissions: SCOPE_PERMISSIONS_OVERRIDE_PARENT
                  rules:
                    - actions: ["invoke", "invoke_membership", "register", "deregister"]
                      effect: EFFECT_ALLOW
                      roles: ["platform_admin"]
                    - actions: ["invoke", "invoke_membership", "register", "deregister"]
                      effect: EFFECT_ALLOW
                      roles: ["domain_admin"]
                    - actions: ["invoke", "invoke_membership"]
                      effect: EFFECT_ALLOW
                      roles: ["chat_user", "relationship_manager"]
                """;
    }

    static String wildcardActionForRole(String role) {
        return """
                apiVersion: api.cerbos.dev/v1
                resourcePolicy:
                  version: "default"
                  resource: agent
                  scope: "acme"
                  scopePermissions: SCOPE_PERMISSIONS_REQUIRE_PARENTAL_CONSENT_FOR_ALLOWS
                  rules:
                    - actions: ["*"]
                      effect: EFFECT_ALLOW
                      roles: ["%s"]
                """.formatted(role);
    }

    static String wildcardInOneRule() {
        return """
                apiVersion: api.cerbos.dev/v1
                resourcePolicy:
                  version: "default"
                  resource: agent
                  scope: "acme"
                  scopePermissions: SCOPE_PERMISSIONS_REQUIRE_PARENTAL_CONSENT_FOR_ALLOWS
                  rules:
                    - actions: ["invoke", "*"]
                      effect: EFFECT_ALLOW
                      roles: ["domain_admin"]
                    - actions: ["invoke", "invoke_membership"]
                      effect: EFFECT_ALLOW
                      roles: ["chat_user", "relationship_manager"]
                """;
    }

    static String wildcardRoleAllow() {
        return """
                apiVersion: api.cerbos.dev/v1
                resourcePolicy:
                  version: "default"
                  resource: agent
                  scope: "acme"
                  scopePermissions: SCOPE_PERMISSIONS_REQUIRE_PARENTAL_CONSENT_FOR_ALLOWS
                  rules:
                    - actions: ["invoke"]
                      effect: EFFECT_ALLOW
                      roles: ["*"]
                """;
    }

    /** Grants relationship_manager an explicit membership-probe rule (intent excluded membership). */
    static String rmMembershipGrant() {
        return """
                apiVersion: api.cerbos.dev/v1
                resourcePolicy:
                  version: "default"
                  resource: agent
                  scope: "acme"
                  scopePermissions: SCOPE_PERMISSIONS_REQUIRE_PARENTAL_CONSENT_FOR_ALLOWS
                  rules:
                    - actions: ["invoke", "invoke_membership", "register", "deregister"]
                      effect: EFFECT_ALLOW
                      roles: ["platform_admin"]
                    - actions: ["invoke", "invoke_membership", "register", "deregister"]
                      effect: EFFECT_ALLOW
                      roles: ["domain_admin"]
                    - actions: ["invoke"]
                      effect: EFFECT_ALLOW
                      roles: ["chat_user", "relationship_manager"]
                    - actions: ["invoke_membership"]
                      effect: EFFECT_ALLOW
                      roles: ["chat_user", "relationship_manager"]
                """;
    }

    /** Grants domain_admin register+deregister explicitly (intent excluded register). */
    static String daRegisterGrant() {
        return compliant("acme"); // domain_admin already gets register/deregister in the golden body
    }

    /** chat_user invoke gated on the WRONG classification (intent sanctioned "internal"). */
    static String wrongClassificationCondition() {
        return """
                apiVersion: api.cerbos.dev/v1
                resourcePolicy:
                  version: "default"
                  resource: agent
                  scope: "acme"
                  scopePermissions: SCOPE_PERMISSIONS_REQUIRE_PARENTAL_CONSENT_FOR_ALLOWS
                  rules:
                    - actions: ["invoke", "invoke_membership", "register", "deregister"]
                      effect: EFFECT_ALLOW
                      roles: ["platform_admin"]
                    - actions: ["invoke", "invoke_membership", "register", "deregister"]
                      effect: EFFECT_ALLOW
                      roles: ["domain_admin"]
                    - actions: ["invoke", "invoke_membership"]
                      effect: EFFECT_ALLOW
                      roles: ["chat_user", "relationship_manager"]
                      condition:
                        match:
                          expr: 'R.attr.data_classification == "confidential-pii"'
                """;
    }

    /** chat_user invoke gated WITHOUT a has() guard — errors (fail-open via base) on a missing attribute. */
    static String unguardedCondition() {
        return """
                apiVersion: api.cerbos.dev/v1
                resourcePolicy:
                  version: "default"
                  resource: agent
                  scope: "acme"
                  scopePermissions: SCOPE_PERMISSIONS_REQUIRE_PARENTAL_CONSENT_FOR_ALLOWS
                  rules:
                    - actions: ["invoke", "invoke_membership", "register", "deregister"]
                      effect: EFFECT_ALLOW
                      roles: ["platform_admin"]
                    - actions: ["invoke", "invoke_membership", "register", "deregister"]
                      effect: EFFECT_ALLOW
                      roles: ["domain_admin"]
                    - actions: ["invoke", "invoke_membership"]
                      effect: EFFECT_ALLOW
                      roles: ["chat_user", "relationship_manager"]
                      condition:
                        match:
                          expr: 'R.attr.data_classification == "internal"'
                """;
    }

    /** Drops chat_user entirely — the (invoke/invoke_membership, chat_user) tuples fall through. */
    static String omitsChatUser() {
        return """
                apiVersion: api.cerbos.dev/v1
                resourcePolicy:
                  version: "default"
                  resource: agent
                  scope: "acme"
                  scopePermissions: SCOPE_PERMISSIONS_REQUIRE_PARENTAL_CONSENT_FOR_ALLOWS
                  rules:
                    - actions: ["invoke", "invoke_membership", "register", "deregister"]
                      effect: EFFECT_ALLOW
                      roles: ["platform_admin"]
                    - actions: ["invoke", "invoke_membership", "register", "deregister"]
                      effect: EFFECT_ALLOW
                      roles: ["domain_admin"]
                    - actions: ["invoke"]
                      effect: EFFECT_ALLOW
                      roles: ["relationship_manager"]
                """;
    }

    /** Drops relationship_manager coverage — its base tuples fall through. */
    static String omitsRelationshipManager() {
        return """
                apiVersion: api.cerbos.dev/v1
                resourcePolicy:
                  version: "default"
                  resource: agent
                  scope: "acme"
                  scopePermissions: SCOPE_PERMISSIONS_REQUIRE_PARENTAL_CONSENT_FOR_ALLOWS
                  rules:
                    - actions: ["invoke", "invoke_membership", "register", "deregister"]
                      effect: EFFECT_ALLOW
                      roles: ["platform_admin"]
                    - actions: ["invoke", "invoke_membership", "register", "deregister"]
                      effect: EFFECT_ALLOW
                      roles: ["domain_admin"]
                    - actions: ["invoke", "invoke_membership"]
                      effect: EFFECT_ALLOW
                      roles: ["chat_user"]
                """;
    }

    /** Drops deregister for platform_admin — that base tuple falls through. */
    static String omitsPlatformAdminDeregister() {
        return """
                apiVersion: api.cerbos.dev/v1
                resourcePolicy:
                  version: "default"
                  resource: agent
                  scope: "acme"
                  scopePermissions: SCOPE_PERMISSIONS_REQUIRE_PARENTAL_CONSENT_FOR_ALLOWS
                  rules:
                    - actions: ["invoke", "invoke_membership", "register"]
                      effect: EFFECT_ALLOW
                      roles: ["platform_admin"]
                    - actions: ["invoke", "invoke_membership", "register", "deregister"]
                      effect: EFFECT_ALLOW
                      roles: ["domain_admin"]
                    - actions: ["invoke", "invoke_membership"]
                      effect: EFFECT_ALLOW
                      roles: ["chat_user", "relationship_manager"]
                """;
    }
}
