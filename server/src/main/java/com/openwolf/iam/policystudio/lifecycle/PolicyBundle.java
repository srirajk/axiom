package com.openwolf.iam.policystudio.lifecycle;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * An IMMUTABLE, content-addressed full policy bundle for one tenant (Axiom Story C5). A candidate is a
 * WHOLE snapshot — base policies + all required scope-chain policies + imported derived-roles / variables
 * + the manifests used for validation + the test metadata that certified it — never a partial, mutable
 * file. Its {@code bundleId} ({@code b_<sha256>}) is derived from the canonical full-bundle bytes by
 * {@link BundleCanonicalizer}, so two bundles with identical content have identical ids and any change
 * yields a different id.
 *
 * <p><b>Every policy in the snapshot uses {@code bundleId} as its {@code policyVersion}.</b> The files
 * are stored with the reproducible {@link BundleCanonicalizer#BUNDLE_VERSION_SENTINEL} in that position;
 * {@link #renderedFiles()} stamps the concrete id back in for staging / {@code cerbos compile} / probing.
 *
 * <p>The record is immutable and its id is content-addressed, so a stored bundle cannot be mutated in
 * place: {@link #verifyIntegrity(BundleCanonicalizer)} recomputes the id from the bytes and rejects any
 * tamper (C5.4).
 *
 * @param bundleId        the content-addressed identity ({@code b_<sha256>})
 * @param tenantId        the tenant this bundle is for
 * @param files           base + scope-chain + derived-roles / variables + manifest files (sentinel form)
 * @param manifestRefs    content refs of the manifests used for validation
 * @param testMetadata    the fixture matrix / oracle / PDP that certified the bundle
 * @param canonicalContent the exact canonical bytes the id was derived from (kept for evidence + re-hash)
 */
public record PolicyBundle(
        String bundleId,
        String tenantId,
        List<BundleFile> files,
        List<String> manifestRefs,
        BundleTestMetadata testMetadata,
        String canonicalContent) {

    public PolicyBundle {
        files = List.copyOf(files);
        manifestRefs = List.copyOf(manifestRefs);
    }

    /**
     * Materialise an immutable bundle from its constituent files (authored with the version sentinel),
     * manifest refs and test metadata. The id is derived from the canonical bytes.
     */
    public static PolicyBundle materialize(String tenantId, List<BundleFile> files, List<String> manifestRefs,
                                           BundleTestMetadata testMetadata, BundleCanonicalizer canon) {
        if (tenantId == null || tenantId.isBlank()) {
            throw new IllegalArgumentException("tenantId must be set");
        }
        assertUniqueResourcePolicyIdentities(files);
        String content = canon.canonicalContent(tenantId, files, manifestRefs, testMetadata, null);
        String id = canon.bundleId(content);
        return new PolicyBundle(id, tenantId, files, manifestRefs, testMetadata, content);
    }

    /**
     * A tenant-wide snapshot may contain many resources and scopes, but never two definitions for the
     * same Cerbos identity. Enforce this before hashing so an ambiguous bundle cannot pass review and
     * fail only when the promotion probe stages it under different file names.
     */
    private static void assertUniqueResourcePolicyIdentities(List<BundleFile> files) {
        Map<String, Boolean> paths = new LinkedHashMap<>();
        Map<ResourcePolicyIdentity, String> firstPath = new LinkedHashMap<>();
        for (BundleFile file : files) {
            if (paths.putIfAbsent(file.path(), Boolean.TRUE) != null) {
                throw new IllegalArgumentException("duplicate bundle file path '" + file.path()
                        + "' — canonicalization and content recovery require one file per path");
            }
            ResourcePolicyIdentity.fromYaml(file.yaml()).ifPresent(identity -> {
                if (!BundleCanonicalizer.BUNDLE_VERSION_SENTINEL.equals(identity.version())) {
                    throw new IllegalArgumentException("resource policy file '" + file.path()
                            + "' must use bundle version sentinel '"
                            + BundleCanonicalizer.BUNDLE_VERSION_SENTINEL + "', not '"
                            + identity.version() + "'");
                }
                String existing = firstPath.putIfAbsent(identity, file.path());
                if (existing != null) {
                    throw new IllegalArgumentException("duplicate resource policy identity '"
                            + identity.resource() + "@" + identity.scope() + "#" + identity.version()
                            + "' in bundle files '"
                            + existing + "' and '" + file.path() + "'");
                }
            });
        }
    }

    /**
     * The deployable form: resource-policy version sentinels are replaced by the concrete {@code bundleId},
     * while global module names and their imports are namespaced by that same id. This keeps an active
     * bundle's derived-role/variable dependencies immutable. Never mutates this record.
     */
    public List<BundleFile> renderedFiles() {
        return BundleModuleVersioner.render(files, bundleId);
    }

    /**
     * Recompute the id from the canonical bytes and reject any in-place mutation (C5.4). A stored bundle
     * whose files, manifest refs, or test metadata were altered while keeping the same id fails here.
     *
     * @throws BundleTamperException if the recomputed id does not match {@code bundleId}
     */
    public void verifyIntegrity(BundleCanonicalizer canon) {
        String recomputedContent = canon.canonicalContent(tenantId, files, manifestRefs, testMetadata, bundleId);
        String recomputedId = canon.bundleId(recomputedContent);
        if (!recomputedId.equals(bundleId) || !recomputedContent.equals(canonicalContent)) {
            throw new BundleTamperException(
                    "policy bundle '" + bundleId + "' failed integrity: recomputed id is '" + recomputedId
                            + "' and canonical content match=" + recomputedContent.equals(canonicalContent)
                            + " — a promoted bundle is immutable and cannot be edited in place");
        }
    }
}
