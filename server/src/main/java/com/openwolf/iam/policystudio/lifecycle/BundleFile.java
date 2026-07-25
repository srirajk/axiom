package com.openwolf.iam.policystudio.lifecycle;

/**
 * One file inside an immutable policy bundle (Axiom Story C5): a base policy, a scope-chain policy, an
 * imported derived-roles / variables module, or a manifest used for validation. Its {@code yaml} is the
 * canonical form the bundle hash is computed over, with the policy's own version field carrying the
 * {@link BundleCanonicalizer#BUNDLE_VERSION_SENTINEL} placeholder — never the concrete bundle id — so
 * the content-addressed identity is reproducible and free of self-reference.
 *
 * @param path a stable, sortable path within the bundle
 * @param yaml the canonical UTF-8/LF YAML with the version sentinel in the policyVersion position
 */
public record BundleFile(String path, String yaml) {

    public BundleFile {
        if (path == null || path.isBlank()) {
            throw new IllegalArgumentException("bundle file path must be set");
        }
        if (yaml == null) {
            throw new IllegalArgumentException("bundle file yaml must be set");
        }
    }
}
