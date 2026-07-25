package com.openwolf.iam.policystudio.lifecycle;

import org.junit.jupiter.api.Test;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class ResourcePolicyIdentityTest {

    @Test
    void authoredChildReplacesSeededIdentityWithoutRemovingRootModuleOrOtherChild() {
        BundleFile root = policy("policies/agent_resource.yaml", "agent", "", "EFFECT_ALLOW");
        BundleFile seeded = policy("policies/tenant_default_agent.yaml", "agent", "default", "EFFECT_DENY");
        BundleFile otherChild = policy(
                "policies/tenant_default_relationship.yaml", "relationship", "default", "EFFECT_DENY");
        BundleFile module = new BundleFile("policies/derived.yaml", """
                apiVersion: api.cerbos.dev/v1
                derivedRoles:
                  name: business_roles
                  definitions: []
                """);
        BundleFile authored = policy(
                "policies/agent@default.yaml", "agent", "default", "EFFECT_ALLOW");

        Map<String, BundleFile> assembled = new LinkedHashMap<>();
        for (BundleFile file : List.of(root, seeded, otherChild, module)) {
            assembled.put(file.path(), file);
        }
        ResourcePolicyIdentity.putReplacing(assembled, authored);

        assertThat(assembled.keySet())
                .containsExactlyInAnyOrder(root.path(), otherChild.path(), module.path(), authored.path())
                .doesNotContain(seeded.path());
        assertThat(assembled.values()).filteredOn(file -> ResourcePolicyIdentity.fromYaml(file.yaml())
                        .map(new ResourcePolicyIdentity(
                                "agent", "default", BundleCanonicalizer.BUNDLE_VERSION_SENTINEL)::equals)
                        .orElse(false))
                .containsExactly(authored);
    }

    @Test
    void bundleRefusesDuplicateSemanticIdentityEvenWhenFileNamesDiffer() {
        BundleFile seeded = policy("policies/tenant_default_agent.yaml", "agent", "default", "EFFECT_DENY");
        BundleFile authored = policy("policies/agent@default.yaml", "agent", "default", "EFFECT_ALLOW");

        assertThatThrownBy(() -> PolicyBundle.materialize(
                "default", List.of(seeded, authored), List.of(),
                new BundleTestMetadata("fixtures", 1, "oracle", "pdp"), new BundleCanonicalizer()))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("duplicate resource policy identity 'agent@default#__BUNDLE_VERSION__'")
                .hasMessageContaining(seeded.path())
                .hasMessageContaining(authored.path());
    }

    @Test
    void malformedAndAmbiguousDocumentsFailClosedWhileNamedModuleIsAccepted() {
        BundleTestMetadata metadata = new BundleTestMetadata("fixtures", 1, "oracle", "pdp");
        BundleCanonicalizer canonicalizer = new BundleCanonicalizer();

        for (String invalid : List.of(
                "resourcePolicy: [",
                "resourcePolicy:\n  resource: agent\n  resource: relationship\n  version: __BUNDLE_VERSION__\n",
                "resourcePolicy: []\n",
                "resourcePolicy:\n  version: __BUNDLE_VERSION__\n  scope: default\n",
                "apiVersion: api.cerbos.dev/v1\nunknownDocument: {}\n")) {
            assertThatThrownBy(() -> PolicyBundle.materialize(
                    "default", List.of(new BundleFile("bad.yaml", invalid)), List.of(),
                    metadata, canonicalizer))
                    .isInstanceOf(IllegalArgumentException.class);
        }

        BundleFile validModule = new BundleFile("derived.yaml", """
                apiVersion: api.cerbos.dev/v1
                derivedRoles:
                  name: business_roles
                  definitions: []
                """);
        assertThat(PolicyBundle.materialize(
                "default", List.of(validModule), List.of(), metadata, canonicalizer).files())
                .containsExactly(validModule);
    }

    @Test
    void pathCollisionCannotOverwriteDifferentIdentityOrModule() {
        String path = "policies/shared.yaml";
        Map<String, BundleFile> policies = new LinkedHashMap<>();
        policies.put(path, policy(path, "agent", "default", "EFFECT_DENY"));

        assertThatThrownBy(() -> ResourcePolicyIdentity.putReplacing(
                policies, policy(path, "relationship", "default", "EFFECT_DENY")))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("bundle path collision");

        Map<String, BundleFile> modules = new LinkedHashMap<>();
        modules.put(path, new BundleFile(path, """
                apiVersion: api.cerbos.dev/v1
                derivedRoles:
                  name: first
                  definitions: []
                """));
        assertThatThrownBy(() -> ResourcePolicyIdentity.putReplacing(
                modules, new BundleFile(path, """
                        apiVersion: api.cerbos.dev/v1
                        derivedRoles:
                          name: second
                          definitions: []
                        """)))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("bundle path collision");
    }

    @Test
    void bundleRejectsDuplicatePathsBeforeCanonicalizationForPoliciesAndModules() {
        BundleTestMetadata metadata = new BundleTestMetadata("fixtures", 1, "oracle", "pdp");
        BundleCanonicalizer canonicalizer = new BundleCanonicalizer();
        String path = "policies/collision.yaml";

        assertThatThrownBy(() -> PolicyBundle.materialize(
                "default",
                List.of(
                        policy(path, "agent", "default", "EFFECT_DENY"),
                        policy(path, "relationship", "default", "EFFECT_DENY")),
                List.of(), metadata, canonicalizer))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("duplicate bundle file path")
                .hasMessageContaining(path);

        BundleFile module = new BundleFile(path, """
                apiVersion: api.cerbos.dev/v1
                derivedRoles:
                  name: business_roles
                  definitions: []
                """);
        assertThatThrownBy(() -> PolicyBundle.materialize(
                "default", List.of(module, module), List.of(), metadata, canonicalizer))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("duplicate bundle file path")
                .hasMessageContaining(path);
    }

    private static BundleFile policy(String path, String resource, String scope, String effect) {
        return new BundleFile(path, """
                apiVersion: api.cerbos.dev/v1
                resourcePolicy:
                  version: __BUNDLE_VERSION__
                  resource: %s
                  scope: "%s"
                  rules:
                    - actions: [invoke]
                      effect: %s
                      roles: [platform_admin]
                """.formatted(resource, scope, effect));
    }
}
