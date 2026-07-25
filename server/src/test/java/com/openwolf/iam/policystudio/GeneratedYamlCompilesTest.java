package com.openwolf.iam.policystudio;

import com.openwolf.iam.test.AxiomTestPolicyRoot;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

/** AXM-1 platform-policy generation proof; the target kind is the explicit iam-resource contract. */
class GeneratedYamlCompilesTest {
    private final PolicyYamlParser parser = new PolicyYamlParser();
    private final GeneratedPolicyValidator validator = new GeneratedPolicyValidator();
    private final CanonicalPolicyWriter writer = new CanonicalPolicyWriter();
    private final CerbosCompileGate gate = new CerbosCompileGate(AxiomTestPolicyRoot.cerbosImage(), 90);

    @BeforeEach
    void requireCerbos() {
        Assumptions.assumeTrue(gate.isAvailable(), "isolated pinned Cerbos is unavailable");
    }

    private static ManifestVocabulary platformVocabulary() {
        return new ManifestVocabulary("iam-resource",
                Set.of("create", "read", "update", "delete", "list", "export", "approve_policy", "deploy_policy"),
                Set.of(), Set.of("resource_type", "tenant_id", "domain_id", "owner_id"),
                Set.of("platform_admin"), Set.of("iam_derived_roles"));
    }

    private static BaseCeiling platformCeiling() {
        return new BaseCeiling("iam-resource", Set.of(
                new BaseCeiling.Tuple("create", "platform_admin"),
                new BaseCeiling.Tuple("read", "platform_admin"),
                new BaseCeiling.Tuple("update", "platform_admin"),
                new BaseCeiling.Tuple("delete", "platform_admin"),
                new BaseCeiling.Tuple("list", "platform_admin"),
                new BaseCeiling.Tuple("export", "platform_admin"),
                new BaseCeiling.Tuple("approve_policy", "platform_admin"),
                new BaseCeiling.Tuple("deploy_policy", "platform_admin")), true,
                Set.of("iam-resource@"));
    }

    private PolicyAuthoringRequest request(String scope) {
        return new PolicyAuthoringRequest("Narrow IAM platform access to the requested tenant.",
                platformVocabulary(), TenantScope.of(scope), false, platformCeiling());
    }

    private String candidate(String scope) {
        return """
                apiVersion: api.cerbos.dev/v1
                resourcePolicy:
                  version: "default"
                  resource: iam-resource
                  scope: "%s"
                  scopePermissions: SCOPE_PERMISSIONS_REQUIRE_PARENTAL_CONSENT_FOR_ALLOWS
                  importDerivedRoles: [iam_derived_roles]
                  rules:
                    - actions: ["create", "read", "update", "delete", "list", "export", "approve_policy", "deploy_policy"]
                      effect: EFFECT_ALLOW
                      roles: ["platform_admin"]
                """.formatted(scope);
    }

    private StudioGenerationResult generate(String authorScope, String candidateScope) {
        PolicyStudioGenerationService service = new PolicyStudioGenerationService(
                request -> candidate(candidateScope), parser, validator, writer, gate,
                AxiomTestPolicyRoot.policies().toString());
        return service.generate(request(authorScope));
    }

    @Test
    void acceptedPlatformCandidateCompilesAndIsCanonical() {
        StudioGenerationResult result = generate("tenant-a", "tenant-a");
        Assumptions.assumeTrue(result.violations().stream().noneMatch(v ->
                        v.contains("docker API") || v.contains("Cannot connect to the Docker daemon")),
                () -> "live Cerbos compile unavailable: " + result.violations());

        assertThat(result.accepted()).as("platform generation violations: %s", result.violations()).isTrue();
        assertThat(result.stage()).isEqualTo(StudioGenerationResult.Stage.ACCEPTED);
        assertThat(result.canonicalYaml()).contains("resource: iam-resource").contains("scope: tenant-a");
    }

    @Test
    void platformCandidateCannotEscapeTheAuthorTenant() {
        StudioGenerationResult result = generate("tenant-a", "tenant-b");

        assertThat(result.accepted()).isFalse();
        assertThat(result.canonicalYaml()).isNull();
    }
}
