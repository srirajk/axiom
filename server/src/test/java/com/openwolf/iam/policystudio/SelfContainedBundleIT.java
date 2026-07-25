package com.openwolf.iam.policystudio;

import com.openwolf.iam.policystudio.lifecycle.BundleCanonicalizer;
import com.openwolf.iam.policystudio.lifecycle.BundleFile;
import com.openwolf.iam.policystudio.lifecycle.BundleTestMetadata;
import com.openwolf.iam.policystudio.lifecycle.PolicyBundle;
import com.openwolf.iam.policystudio.lifecycle.SelfContainedBundleAssembler;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * S3, Bug B — a candidate bundle is a WHOLE self-contained set (base ceiling + every required scope-chain
 * policy + imported derived-roles + the manifests used for validation), not one root + one tenant child
 * that silently leans on a mutable external base directory.
 *
 * <ol>
 *   <li><b>Content-addressed over the whole set:</b> the {@code bundleId} changes iff any INCLUDED policy,
 *       derived-role, or manifest changes — and does NOT change when an unrelated (uncaptured) base policy
 *       changes, proving the capture is the focused scope chain, not the whole mutable dir.</li>
 *   <li><b>Compiles from its own captured contents:</b> the candidate {@code cerbos compile}s from ONLY its
 *       captured bytes with the external base dir absent/empty.</li>
 * </ol>
 */
class SelfContainedBundleIT {

    private static final String TENANT = "acme";
    private static final List<String> MANIFEST_REFS = List.of("manifest:agent@sha-selfcontained");

    /** The authored tenant restriction child, in the reproducible version-sentinel form. */
    private static String childSentinel() {
        return """
                apiVersion: api.cerbos.dev/v1
                resourcePolicy:
                  version: %s
                  resource: agent
                  scope: "acme"
                  scopePermissions: SCOPE_PERMISSIONS_REQUIRE_PARENTAL_CONSENT_FOR_ALLOWS
                  rules:
                    - actions: ["invoke", "invoke_membership", "register", "deregister"]
                      effect: EFFECT_ALLOW
                      roles: ["platform_admin"]
                """.formatted(BundleCanonicalizer.BUNDLE_VERSION_SENTINEL);
    }

    private static PolicyBundle materialize(Path baseDir, List<String> manifestRefs) {
        SelfContainedBundleAssembler assembler = new SelfContainedBundleAssembler(baseDir.toString());
        List<BundleFile> files = new ArrayList<>(assembler.captureScopeChain("agent"));
        files.add(new BundleFile("policies/agent@" + TENANT + ".yaml", childSentinel()));
        return PolicyBundle.materialize(TENANT, files, manifestRefs,
                new BundleTestMetadata("fs-selfcontained", 5, "c3-independent-oracle", "cerbos:0.53.0"),
                new BundleCanonicalizer());
    }

    @Test
    void bundleIdCapturesTheWholeScopeChainAndDerivedRolesAndManifests() throws IOException {
        Path base = PolicyStudioFixtures.baseBundleDir();

        String baseline = materialize(base, MANIFEST_REFS).bundleId();

        // The captured set is the scope chain + imported derived roles: at least the agent root + the
        // business_derived_roles module.
        List<BundleFile> captured = new SelfContainedBundleAssembler(base.toString()).captureScopeChain("agent");
        assertThat(captured).extracting(BundleFile::path)
                .anyMatch(p -> p.contains("agent_resource"))
                .anyMatch(p -> p.contains("business_derived_roles"));

        // (a) A one-byte change to an INCLUDED derived-role module changes the id.
        Path mutatedDerivedRoles = copyBaseWithEdit(base, "business_derived_roles.yaml",
                s -> s + "\n# self-contained-identity-probe: mutated\n");
        assertThat(materialize(mutatedDerivedRoles, MANIFEST_REFS).bundleId())
                .as("mutating an INCLUDED derived-role module must change the bundle id")
                .isNotEqualTo(baseline);

        // (b) A change to an INCLUDED scope-chain policy changes the id.
        Path mutatedRoot = copyBaseWithEdit(base, "agent_resource.yaml",
                s -> s + "\n# self-contained-identity-probe: mutated root\n");
        assertThat(materialize(mutatedRoot, MANIFEST_REFS).bundleId())
                .as("mutating an INCLUDED scope-chain policy must change the bundle id")
                .isNotEqualTo(baseline);

        // (c) A change to the MANIFEST refs changes the id.
        assertThat(materialize(base, List.of("manifest:agent@sha-DIFFERENT")).bundleId())
                .as("mutating a captured manifest ref must change the bundle id")
                .isNotEqualTo(baseline);

        // (d) Adding an UNRELATED resource policy (a different kind) does NOT change the id — the capture is
        //     the focused scope chain for `agent`, not the whole mutable base dir.
        Path withUnrelated = copyBaseWithNewFile(base, "widget_resource.yaml", """
                apiVersion: api.cerbos.dev/v1
                resourcePolicy:
                  version: "default"
                  resource: widget
                  scope: ""
                  rules:
                    - actions: ["view"]
                      effect: EFFECT_ALLOW
                      roles: ["platform_admin"]
                """);
        assertThat(materialize(withUnrelated, MANIFEST_REFS).bundleId())
                .as("an unrelated (uncaptured) base policy must NOT change the self-contained bundle id")
                .isEqualTo(baseline);
    }

    @Test
    void candidateCompilesFromItsOwnCapturedContentsWithNoExternalBaseDir() {
        CerbosCompileGate gate = new CerbosCompileGate(com.openwolf.iam.test.AxiomTestPolicyRoot.cerbosImage(), 90);
        requireRealPdp(gate.isAvailable());

        PolicyBundle candidate = materialize(PolicyStudioFixtures.baseBundleDir(), MANIFEST_REFS);

        // Compile from ONLY the captured, rendered (bundleId-stamped) files — NO external base dir is read.
        CerbosCompileGate.CompileOutcome outcome = gate.compile(candidate.renderedFiles());
        assertThat(outcome.success())
                .as("a self-contained candidate must cerbos-compile from its own captured contents alone: %s",
                        outcome.output())
                .isTrue();
    }

    @Test
    void tenantWideCaptureContainsEveryRuntimeResourceKind() {
        Path repoPolicies = com.openwolf.iam.test.AxiomTestPolicyRoot.policies();
        List<BundleFile> captured = new SelfContainedBundleAssembler(
                repoPolicies.toString()).captureFullPolicySet();

        assertThat(captured).extracting(BundleFile::path)
                .contains("policies/iam_resource.yaml")
                .contains("policies/policy_draft_resource.yaml")
                .contains("policies/policy_approval_resource.yaml")
                .contains("policies/policy_bundle_resource.yaml")
                .contains("policies/business_derived_roles.yaml")
                .contains("policies/policy_studio_derived_roles.yaml");

        assertThat(captured.stream()
                .filter(f -> f.yaml().contains("resourcePolicy:"))
                .allMatch(f -> f.yaml().contains(BundleCanonicalizer.BUNDLE_VERSION_SENTINEL)))
                .as("every resource kind in one tenant snapshot must be stamped with the same bundle id")
                .isTrue();
    }

    // ── temp-base helpers ───────────────────────────────────────────────────────────────────────────

    private interface Edit { String apply(String in); }

    private static Path copyBaseWithEdit(Path base, String fileName, Edit edit) throws IOException {
        Path dir = copyBase(base);
        Path target = dir.resolve(fileName);
        Files.writeString(target, edit.apply(Files.readString(target)), StandardCharsets.UTF_8);
        return dir;
    }

    private static Path copyBaseWithNewFile(Path base, String fileName, String content) throws IOException {
        Path dir = copyBase(base);
        Files.writeString(dir.resolve(fileName), content, StandardCharsets.UTF_8);
        return dir;
    }

    private static Path copyBase(Path base) throws IOException {
        Path dir = Files.createTempDirectory("selfcontained-base-");
        try (Stream<Path> walk = Files.walk(base)) {
            for (Path p : (Iterable<Path>) walk::iterator) {
                if (Files.isRegularFile(p)) {
                    Files.copy(p, dir.resolve(base.relativize(p).toString()));
                }
            }
        }
        return dir;
    }

    private static void requireRealPdp(boolean available) {
        boolean requiredInCi = Boolean.parseBoolean(
                System.getenv().getOrDefault("CONDUIT_DOCKER_REQUIRED", "false"));
        if (requiredInCi) {
            assertThat(available)
                    .as("CONDUIT_DOCKER_REQUIRED=true but pinned Cerbos is unavailable; this compile proof must run")
                    .isTrue();
        } else {
            Assumptions.assumeTrue(available, "pinned Cerbos unavailable — skipping self-contained compile proof");
        }
    }
}
