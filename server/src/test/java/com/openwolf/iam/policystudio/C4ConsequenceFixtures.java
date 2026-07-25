package com.openwolf.iam.policystudio;

import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Deterministic fixtures for the Axiom Story C4 consequence-diff harness. Two immutable tenant-child
 * bundles at scope {@code acme} — a "current" and a "candidate" — that differ in exactly the cells the
 * matrix probes, plus the C3-style principal×resource×action matrix. All truth is produced by the
 * in-process {@link LocalPdpDecisionSource} (the C3 fidelity evaluator); NO real LLM and NO Docker are
 * involved, so the harness reproduces byte-for-byte on any JDK 25 box.
 *
 * <p>The candidate both WIDENS (chat_user / relationship_manager gain invoke + membership — the
 * over-permission alarm) and NARROWS (domain_admin loses register/deregister — access removed),
 * exercising both delta directions.
 */
final class C4ConsequenceFixtures {

    private C4ConsequenceFixtures() {}

    static final String TENANT = "acme";
    static final String SIGNING_KEY = "c4-test-consequence-signing-key";

    // ── the two immutable bundles (scope acme, parental-consent posture) ────────────────────────

    /** Current: chat_user/relationship_manager are DENIED invoke+membership; domain_admin has register. */
    static String currentBody() {
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
                    - actions: ["invoke", "invoke_membership"]
                      effect: EFFECT_ALLOW
                      roles: ["domain_admin"]
                    - actions: ["register", "deregister"]
                      effect: EFFECT_ALLOW
                      roles: ["domain_admin"]
                    - actions: ["invoke", "invoke_membership"]
                      effect: EFFECT_DENY
                      roles: ["chat_user", "relationship_manager"]
                """;
    }

    /** Candidate: chat_user/relationship_manager GAIN invoke+membership (widen); domain_admin LOSES
     *  register/deregister (narrow). */
    static String candidateBody() {
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
                    - actions: ["invoke", "invoke_membership"]
                      effect: EFFECT_ALLOW
                      roles: ["domain_admin"]
                    - actions: ["register", "deregister"]
                      effect: EFFECT_DENY
                      roles: ["domain_admin"]
                    - actions: ["invoke", "invoke_membership"]
                      effect: EFFECT_ALLOW
                      roles: ["chat_user", "relationship_manager"]
                """;
    }

    /** A THIRD candidate that differs from {@link #candidateBody()} in exactly ONE cell
     *  (relationship_manager invoke_membership stays denied) — for the "change one delta cell → new
     *  hash" binding test. */
    static String candidateBodyOneCellDifferent() {
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
                    - actions: ["invoke", "invoke_membership"]
                      effect: EFFECT_ALLOW
                      roles: ["domain_admin"]
                    - actions: ["register", "deregister"]
                      effect: EFFECT_DENY
                      roles: ["domain_admin"]
                    - actions: ["invoke"]
                      effect: EFFECT_ALLOW
                      roles: ["chat_user", "relationship_manager"]
                    - actions: ["invoke_membership"]
                      effect: EFFECT_DENY
                      roles: ["chat_user", "relationship_manager"]
                """;
    }

    static PolicyIR ir(String body) {
        return new PolicyYamlParser().parse(body);
    }

    static CanonicalPolicyWriter writer() {
        return new CanonicalPolicyWriter();
    }

    static BundleSnapshot bundle(String body) {
        return BundleSnapshot.of(ir(body), PolicyStudioFixtures.agentCeiling(), writer());
    }

    static ManifestVocabulary vocab() {
        return PolicyStudioFixtures.agentVocab();
    }

    static PdpDecisionSource localPdp() {
        return new LocalPdpDecisionSource(new PolicyExpectationEvaluator(new ConditionEvaluator()));
    }

    static ConsequenceDiffService diffService() {
        return new ConsequenceDiffService();
    }

    // ── the sampled matrix (same-tenant cells; no conditions ⇒ fully decidable) ───────────────────

    private static FixtureCell cell(Set<String> roles, String action, String label) {
        return new FixtureCell(roles, TENANT, Map.of(), TENANT, Map.of(), action, label);
    }

    static ConsequenceFixtureMatrix matrix() {
        return ConsequenceFixtureMatrix.of(List.of(
                cell(Set.of("chat_user"), "invoke", "chatUser_invoke"),
                cell(Set.of("chat_user"), "invoke_membership", "chatUser_membership"),
                cell(Set.of("relationship_manager"), "invoke", "rm_invoke"),
                cell(Set.of("domain_admin"), "register", "domainAdmin_register"),
                cell(Set.of("platform_admin"), "invoke", "platformAdmin_invoke")));
    }

    /** A smaller matrix (drops one cell) — for the "change the fixture set → new hash" binding test. */
    static ConsequenceFixtureMatrix smallerMatrix() {
        return ConsequenceFixtureMatrix.of(List.of(
                cell(Set.of("chat_user"), "invoke", "chatUser_invoke"),
                cell(Set.of("relationship_manager"), "invoke", "rm_invoke")));
    }

    // ── prose seams ───────────────────────────────────────────────────────────────────────────────

    /** An LLM prose seam that ALWAYS ERRORS — proves the delta is correct without any LLM (C4.1). */
    static ConsequenceProseModelClient erroringProse() {
        return review -> {
            throw new IllegalStateException("LLM prose seam is intentionally erroring in this test");
        };
    }

    /** A benign deterministic prose seam (no network) that echoes the delta count. */
    static ConsequenceProseModelClient stubProse() {
        return review -> "This change introduces " + review.deltas().size()
                + " decision change(s); over-permission alarm=" + review.overPermissionAlarm() + ".";
    }
}
