package com.openwolf.iam.policystudio.lifecycle;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.nio.file.Files;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Regression for the S4/S5 break-glass runtime-load failure: a self-contained bundle carries a scoped
 * tenant child ({@code scope: "acme"}) AND its same-version root ceiling ({@code scope: ""}), and the child
 * declares the root as its ancestor. Cerbos' {@code watchForChanges} looks an ancestor up in the CURRENT
 * index as each file's storage event is processed, so if the scoped child is written (and indexed) before
 * its root, the reload fails with "failed to load ancestor … policy not found" and Cerbos keeps the last
 * valid (un-enforced) state. {@link PromotedBundleLoader} must therefore write ANCESTOR-FIRST — shallower
 * scopes before deeper children — even though {@code renderedFiles()} is path-sorted (which places
 * {@code agent@acme.yaml} before {@code agent_resource.yaml}).
 */
class PromotedBundleLoaderAncestorOrderTest {

    private static final String SENT = BundleCanonicalizer.BUNDLE_VERSION_SENTINEL;

    private static String rootBody() {
        return """
                apiVersion: api.cerbos.dev/v1
                resourcePolicy:
                  version: "%s"
                  resource: agent
                  scope: ""
                  rules:
                    - actions: ["invoke"]
                      effect: EFFECT_ALLOW
                      roles: ["platform_admin"]
                """.formatted(SENT);
    }

    private static String childBody() {
        return """
                apiVersion: api.cerbos.dev/v1
                resourcePolicy:
                  version: "%s"
                  resource: agent
                  scope: "acme"
                  scopePermissions: SCOPE_PERMISSIONS_REQUIRE_PARENTAL_CONSENT_FOR_ALLOWS
                  rules:
                    - actions: ["invoke"]
                      effect: EFFECT_ALLOW
                      roles: ["platform_admin"]
                """.formatted(SENT);
    }

    @Test
    void scopeDepthRanksRootBelowScopedChildren() {
        assertThat(PromotedBundleLoader.scopeDepth("resourcePolicy:\n  scope: \"\"\n")).isZero();
        assertThat(PromotedBundleLoader.scopeDepth("resourcePolicy:\n  scope: \"acme\"\n")).isEqualTo(1);
        assertThat(PromotedBundleLoader.scopeDepth("resourcePolicy:\n  scope: acme\n")).isEqualTo(1);
        assertThat(PromotedBundleLoader.scopeDepth("resourcePolicy:\n  scope: \"acme.eng\"\n")).isEqualTo(2);
        // scopePermissions must NOT be mistaken for the scope line.
        assertThat(PromotedBundleLoader.scopeDepth(
                "resourcePolicy:\n  scopePermissions: SCOPE_PERMISSIONS_REQUIRE_PARENTAL_CONSENT_FOR_ALLOWS\n  scope: \"acme\"\n"))
                .isEqualTo(1);
        assertThat(PromotedBundleLoader.publicationTier("derivedRoles:\n  name: roles\n"))
                .as("a versioned global module must publish before a root that imports it")
                .isEqualTo(-1);
        assertThat(PromotedBundleLoader.publicationTier("exportVariables:\n  name: values\n"))
                .isEqualTo(-1);
    }

    @Test
    void loaderWritesTheRootAncestorBeforeTheScopedChild(@TempDir Path runtimeDir) throws java.io.IOException {
        // The child sorts BEFORE the root by path ('@' < '_'), so renderedFiles() hands them child-first —
        // the exact losing order that broke the watch reload.
        PolicyBundle bundle = PolicyBundle.materialize(
                "acme",
                List.of(new BundleFile("policies/agent@acme.yaml", childBody()),
                        new BundleFile("policies/agent_resource.yaml", rootBody())),
                List.of("manifest:agent@sha-order-test"),
                new BundleTestMetadata("fs-order-test", 1, "c3-independent-oracle", "cerbos:0.53.0"),
                new BundleCanonicalizer());

        // settle 0, single pass — no live watcher to serialize, so keep the unit test instant.
        List<Path> written = new PromotedBundleLoader(runtimeDir.toString(), 0L, 1).load(bundle);
        assertThat(written).hasSize(2);
        assertThat(written).allSatisfy(path -> assertThat(Files.readString(path)).isNotBlank());
        try (var files = Files.list(runtimeDir)) {
            assertThat(files.map(path -> path.getFileName().toString()).toList())
                    .noneMatch(name -> name.contains(".publish"));
        }

        int rootIdx = indexOfContains(written, "agent_resource");
        int childIdx = indexOfContains(written, "agent_acme");
        assertThat(rootIdx).as("both files were written").isNotNegative();
        assertThat(childIdx).isNotNegative();
        assertThat(rootIdx)
                .as("the root ceiling (scope \"\") must be written before its scoped child (scope \"acme\")")
                .isLessThan(childIdx);
    }

    private static int indexOfContains(List<Path> paths, String needle) {
        for (int i = 0; i < paths.size(); i++) {
            if (paths.get(i).getFileName().toString().contains(needle)) {
                return i;
            }
        }
        return -1;
    }
}
