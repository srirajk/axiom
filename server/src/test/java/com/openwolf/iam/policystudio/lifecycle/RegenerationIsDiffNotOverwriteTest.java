package com.openwolf.iam.policystudio.lifecycle;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * C5.2 — regeneration is a reviewed diff, never an overwrite. Regenerating against a stored/active bundle
 * yields a NEW candidate bundle (a different id) plus a C4 consequence review; it writes nothing. The
 * stored live bundle's bytes are byte-identical before and after, and the candidate is not persisted —
 * it becomes real only through a separate authorized promotion.
 */
class RegenerationIsDiffNotOverwriteTest {

    @Test
    void regenerationYieldsNewBundleAndDiffLeavingStoredBundleUntouched() {
        PolicyBundle current = C5LifecycleFixtures.bundle(C5LifecycleFixtures.currentBody(), C5LifecycleFixtures.matrixHash());
        PolicyBundle candidate = C5LifecycleFixtures.bundle(C5LifecycleFixtures.candidateBody(), C5LifecycleFixtures.matrixHash());

        PolicyBundleRepository bundles = C5LifecycleFixtures.bundleRepo();
        bundles.save(new PolicyBundleRecord(current, "commit-0"));
        String storedBytesBefore = bundles.findById(current.bundleId()).orElseThrow().getCanonicalContent();

        RegenerationService regen = new RegenerationService(C5LifecycleFixtures.diffService());
        RegenerationResult result = regen.regenerate(
                current, candidate, C5LifecycleFixtures.vocab(),
                C5LifecycleFixtures.snapshotStamped(C5LifecycleFixtures.currentBody(), current.bundleId()),
                C5LifecycleFixtures.snapshotStamped(C5LifecycleFixtures.candidateBody(), candidate.bundleId()),
                C5LifecycleFixtures.matrix(), C5LifecycleFixtures.localPdp());

        // A NEW candidate and a real C4 diff (widening + narrowing consequences).
        assertThat(result.candidate().bundleId()).isEqualTo(candidate.bundleId());
        assertThat(result.candidate().bundleId()).isNotEqualTo(current.bundleId());
        assertThat(result.diff().deltas()).isNotEmpty();
        assertThat(result.diff().overPermissionAlarm()).isTrue();
        assertThat(result.diff().currentBundleId()).isEqualTo(current.bundleId());
        assertThat(result.diff().candidateBundleId()).isEqualTo(candidate.bundleId());

        // The stored/active bundle is byte-identical — regeneration overwrote nothing.
        String storedBytesAfter = bundles.findById(current.bundleId()).orElseThrow().getCanonicalContent();
        assertThat(storedBytesAfter).isEqualTo(storedBytesBefore);

        // The candidate was NOT persisted — it is not live until a separate authorized promotion.
        assertThat(bundles.existsById(candidate.bundleId())).isFalse();
        assertThat(bundles.findByTenantIdOrderByCreatedAtDesc(C5LifecycleFixtures.TENANT)).hasSize(1);
    }
}
