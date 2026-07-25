package com.openwolf.iam.policystudio;

import java.net.URISyntaxException;
import java.nio.file.Path;
import java.util.Set;

/**
 * Deterministic fixtures for the C2 harness: the manifest vocabulary + base ceiling for the
 * {@code agent} resource (mirroring {@code infra/cerbos/policies/agent_resource.yaml} +
 * {@code business_derived_roles.yaml}, copied under {@code test/resources/policystudio/base-bundle}),
 * plus a corpus of known-good and ADVERSARIAL proposed YAML. The validator is deterministic and no
 * real LLM is involved — the stub client (below) replays these.
 */
final class PolicyStudioFixtures {

    private PolicyStudioFixtures() {}

    // ── vocabulary + ceiling (grounded in the copied base bundle) ────────────────────────────

    static ManifestVocabulary agentVocab() {
        return new ManifestVocabulary(
                "agent",
                Set.of("invoke", "invoke_membership", "register", "deregister"),
                Set.of("internal", "confidential", "confidential-pii"),
                Set.of("domain", "audience", "access_mode", "data_classification",
                        "segments", "admin_domains", "domains", "tenant_id"),
                Set.of("platform_admin", "domain_admin", "chat_user", "relationship_manager", "conduit_admin"),
                Set.of("business_derived_roles"));
    }

    /** Every base-allowed (action, role) tuple for {@code agent}, derived roles expanded to parents. */
    static BaseCeiling agentCeiling() {
        return new BaseCeiling(
                "agent",
                Set.of(
                        // platform_admin: full surface
                        new BaseCeiling.Tuple("invoke", "platform_admin"),
                        new BaseCeiling.Tuple("invoke_membership", "platform_admin"),
                        new BaseCeiling.Tuple("register", "platform_admin"),
                        new BaseCeiling.Tuple("deregister", "platform_admin"),
                        // domain_admin: full surface
                        new BaseCeiling.Tuple("invoke", "domain_admin"),
                        new BaseCeiling.Tuple("invoke_membership", "domain_admin"),
                        new BaseCeiling.Tuple("register", "domain_admin"),
                        new BaseCeiling.Tuple("deregister", "domain_admin"),
                        // chat_user / relationship_manager: invoke + membership probe only
                        new BaseCeiling.Tuple("invoke", "chat_user"),
                        new BaseCeiling.Tuple("invoke", "relationship_manager"),
                        new BaseCeiling.Tuple("invoke_membership", "chat_user"),
                        new BaseCeiling.Tuple("invoke_membership", "relationship_manager")),
                /* carriesTenantEqualityBackstop */ true,
                /* reservedIdentities */ Set.of("agent@")); // the base root policy
    }

    static PolicyAuthoringRequest request(String intent, TenantScope author, boolean subscopesEnabled) {
        return new PolicyAuthoringRequest(intent, agentVocab(), author, subscopesEnabled, agentCeiling());
    }

    static Path baseBundleDir() {
        try {
            return Path.of(PolicyStudioFixtures.class.getResource("/policystudio/base-bundle").toURI());
        } catch (URISyntaxException e) {
            throw new IllegalStateException(e);
        }
    }

    // ── corpus ───────────────────────────────────────────────────────────────────────────────

    /** A totally-covering, in-vocabulary, in-subtree tenant restriction child (the golden path). */
    static String candidateWithScope(String scope) {
        return """
                apiVersion: api.cerbos.dev/v1
                resourcePolicy:
                  version: "default"
                  resource: agent
                  scope: "%s"
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
                """.formatted(scope);
    }

    static String compliantAcme() {
        return candidateWithScope("acme");
    }

    /** Adversarial: intent said "also grant tenant B" and the model named tenant "beta". */
    static String scopeEscapeToTenantB() {
        return candidateWithScope("beta");
    }

    /** Adversarial: an out-of-vocabulary action smuggled into an otherwise-total policy. */
    static String outOfVocabularyAction() {
        return """
                apiVersion: api.cerbos.dev/v1
                resourcePolicy:
                  version: "default"
                  resource: agent
                  scope: "acme"
                  scopePermissions: SCOPE_PERMISSIONS_REQUIRE_PARENTAL_CONSENT_FOR_ALLOWS
                  rules:
                    - actions: ["invoke", "invoke_membership", "register", "deregister", "exfiltrate"]
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

    /** Adversarial: an out-of-vocabulary classification literal in a condition. */
    static String outOfVocabularyClassification() {
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
                          expr: "R.attr.data_classification == \\"top-secret\\""
                """;
    }

    /** Adversarial: drops the (register/deregister, domain_admin) tuples — a fall-through hole. */
    static String omitsBaseTuple() {
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
                    - actions: ["invoke", "invoke_membership"]
                      effect: EFFECT_ALLOW
                      roles: ["chat_user", "relationship_manager"]
                """;
    }

    /** Adversarial: a wildcard grant. */
    static String wildcardGrant() {
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
                      roles: ["*"]
                """;
    }

    /** Adversarial: a YAML anchor/alias reuse vector. */
    static String aliasVector() {
        return """
                apiVersion: api.cerbos.dev/v1
                resourcePolicy:
                  version: "default"
                  resource: agent
                  scope: &tenant "acme"
                  aliasScope: *tenant
                  scopePermissions: SCOPE_PERMISSIONS_REQUIRE_PARENTAL_CONSENT_FOR_ALLOWS
                  rules:
                    - actions: ["invoke"]
                      effect: EFFECT_ALLOW
                      roles: ["platform_admin"]
                """;
    }

    /** Adversarial: a custom/explicit YAML tag. */
    static String customTag() {
        return """
                apiVersion: api.cerbos.dev/v1
                resourcePolicy:
                  version: "default"
                  resource: !!python/object/apply:os.system ["id"]
                  scope: "acme"
                  scopePermissions: SCOPE_PERMISSIONS_REQUIRE_PARENTAL_CONSENT_FOR_ALLOWS
                  rules: []
                """;
    }

    /** Adversarial: not a resource policy — a derivedRoles document that would redefine trust. */
    static String derivedRolesDocument() {
        return """
                apiVersion: api.cerbos.dev/v1
                derivedRoles:
                  name: business_derived_roles
                  definitions:
                    - name: tenant_chat_user
                      parentRoles: ["chat_user"]
                      condition:
                        match:
                          expr: "true"
                """;
    }

    /** Adversarial: a root-scope policy (would edit the base ceiling, not narrow it). */
    static String rootScopeRewrite() {
        return """
                apiVersion: api.cerbos.dev/v1
                resourcePolicy:
                  version: "default"
                  resource: agent
                  scope: ""
                  scopePermissions: SCOPE_PERMISSIONS_REQUIRE_PARENTAL_CONSENT_FOR_ALLOWS
                  rules:
                    - actions: ["invoke"]
                      effect: EFFECT_ALLOW
                      roles: ["platform_admin"]
                """;
    }

    /** A stub replaying a fixed proposal — the seam where a real LLM would sit. */
    static PolicyAuthoringModelClient stubReturning(String yaml) {
        return request -> yaml;
    }
}
