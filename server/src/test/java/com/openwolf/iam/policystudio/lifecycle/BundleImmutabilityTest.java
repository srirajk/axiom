package com.openwolf.iam.policystudio.lifecycle;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * C5.4 — a promoted bundle is immutable; editing it in place is rejected. The content-addressed id is a
 * SHA-256 over the canonical full-bundle bytes, so any change to a file, manifest ref, or test metadata
 * that keeps the same id fails the integrity check, and re-materialising the altered content yields a
 * DIFFERENT id (a new bundle, never an edit of the old one).
 */
class BundleImmutabilityTest {

    @Test
    void storedBundleCannotBeMutated() {
        BundleCanonicalizer canon = C5LifecycleFixtures.canon();
        PolicyBundle bundle = C5LifecycleFixtures.bundle(C5LifecycleFixtures.candidateBody(), C5LifecycleFixtures.matrixHash());

        // A genuine bundle passes integrity, and its durable record hashes back to its id.
        bundle.verifyIntegrity(canon);
        PolicyBundleRecord genuine = new PolicyBundleRecord(bundle, "commit-1");
        assertThat(genuine.contentMatchesId(canon)).isTrue();

        // Tamper: alter a file but keep the same id → integrity FAILS.
        List<BundleFile> tamperedFiles = List.of(
                new BundleFile(bundle.files().get(0).path(),
                        bundle.files().get(0).yaml() + "\n# smuggled edit\n"));
        PolicyBundle tampered = new PolicyBundle(bundle.bundleId(), bundle.tenantId(), tamperedFiles,
                bundle.manifestRefs(), bundle.testMetadata(), bundle.canonicalContent());
        assertThatThrownBy(() -> tampered.verifyIntegrity(canon))
                .isInstanceOf(BundleTamperException.class)
                .hasMessageContaining("immutable");

        // Re-materialising the altered content is a NEW bundle with a NEW id — never an edit of the old.
        PolicyBundle rebuilt = PolicyBundle.materialize(bundle.tenantId(), tamperedFiles,
                bundle.manifestRefs(), bundle.testMetadata(), canon);
        assertThat(rebuilt.bundleId()).isNotEqualTo(bundle.bundleId());

        // Durable record with swapped-out canonical bytes but the original id fails the store integrity check.
        PolicyBundle contentSwapped = new PolicyBundle(bundle.bundleId(), bundle.tenantId(), bundle.files(),
                bundle.manifestRefs(), bundle.testMetadata(), "TAMPERED-CANONICAL-BYTES");
        assertThatThrownBy(() -> contentSwapped.verifyIntegrity(canon))
                .isInstanceOf(BundleTamperException.class)
                .hasMessageContaining("canonical content match=false");
        PolicyBundleRecord tamperedRecord = new PolicyBundleRecord(contentSwapped, "commit-1");
        assertThat(tamperedRecord.contentMatchesId(canon)).isFalse();
    }
}
