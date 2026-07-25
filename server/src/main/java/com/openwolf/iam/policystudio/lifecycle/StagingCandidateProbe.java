package com.openwolf.iam.policystudio.lifecycle;

import com.openwolf.iam.policystudio.CerbosCompileGate;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

/**
 * The default {@link CandidateProbe} (Axiom Story C5). It enforces the deterministic version-stamping
 * invariant on every rendered policy — every policy in the snapshot must carry the candidate
 * {@code bundleId} as its {@code policyVersion} and leave no unresolved
 * {@link BundleCanonicalizer#BUNDLE_VERSION_SENTINEL} — and, when the pinned Cerbos is available, stages
 * each rendered file alongside the immutable base bundle and {@code cerbos compile}s it. A compile
 * failure aborts.
 *
 * <p><b>(H2) The compile probe is MANDATORY for promotion.</b> When the pinned Cerbos is unavailable this
 * probe HARD-FAILS the promotion rather than degrading to version-stamp-only — a candidate must never be
 * activated on a compile-less host. (This is stricter than the C4 real-PDP <em>evidence</em> run, which may
 * be skipped on a Cerbos-less box because it is not on the activation path.)
 */
@Component
public class StagingCandidateProbe implements CandidateProbe {

    private static final Logger log = LoggerFactory.getLogger(StagingCandidateProbe.class);

    private final CerbosCompileGate compileGate;
    private final String baseBundleDir;

    public StagingCandidateProbe(
            CerbosCompileGate compileGate,
            @Value("${iam.policy-studio.base-bundle-dir:/app/platform-policy/policies}") String baseBundleDir) {
        this.compileGate = compileGate;
        this.baseBundleDir = baseBundleDir;
    }

    @Override
    public void verify(PolicyBundle candidate) {
        // (1) Deterministic invariant: no sentinel survives, and every VERSION-KEYED policy stamps the
        //     candidate id. A self-contained bundle also carries global, name-keyed modules (derived-roles
        //     / variables) that have no policyVersion field — those are captured verbatim (no sentinel to
        //     stamp), so the stamp requirement applies only to files whose sentinel form declared a version.
        java.util.List<BundleFile> sentinelFiles = candidate.files();
        java.util.List<BundleFile> renderedFiles = candidate.renderedFiles();
        for (int i = 0; i < renderedFiles.size(); i++) {
            BundleFile rendered = renderedFiles.get(i);
            if (rendered.yaml().contains(BundleCanonicalizer.BUNDLE_VERSION_SENTINEL)) {
                throw new IllegalStateException("candidate '" + candidate.bundleId() + "' file '"
                        + rendered.path() + "' still carries the version sentinel after rendering");
            }
            boolean carriedVersion = sentinelFiles.get(i).yaml().contains(BundleCanonicalizer.BUNDLE_VERSION_SENTINEL);
            if (carriedVersion && !rendered.yaml().contains(candidate.bundleId())) {
                throw new IllegalStateException("candidate '" + candidate.bundleId() + "' file '"
                        + rendered.path() + "' does not stamp the bundle id as its policyVersion");
            }
        }

        // (2) Structural: compile the candidate from ONLY its own captured contents (S3, Bug B) — the
        //     bundle is self-contained (base ceiling + scope-chain + imported derived-roles/variables +
        //     tenant child), so no external mutable base dir is read.
        //     (H2) The compile probe is MANDATORY for a promotion — it HARD-FAILS when the pinned Cerbos is
        //     unavailable. A promotion must never degrade to version-stamp-only on a compile-less host.
        if (!compileGate.isAvailable()) {
            throw new IllegalStateException("cerbos compile probe is MANDATORY for promotion but no pinned "
                    + "Cerbos (local binary or Docker image) is available — refusing to promote candidate '"
                    + candidate.bundleId() + "' on a compile-less host (never version-stamp-only)");
        }
        CerbosCompileGate.CompileOutcome outcome = compileGate.compile(renderedFiles);
        if (!outcome.success()) {
            throw new IllegalStateException("candidate '" + candidate.bundleId()
                    + "' failed cerbos compile: " + outcome.output());
        }
        log.debug("candidate '{}' compiled from its own captured contents + version-probed OK", candidate.bundleId());
    }
}
