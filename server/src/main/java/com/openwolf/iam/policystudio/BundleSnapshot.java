package com.openwolf.iam.policystudio;

/**
 * An IMMUTABLE full policy-bundle snapshot identified by a content-addressed {@code bundleId} (Axiom
 * Story C4). The consequence diff runs real PDP evaluations against TWO of these — the request's
 * captured current bundle and the staged candidate — and <b>never swaps the live pointer</b> to
 * compute a diff. Each snapshot is a value: the shared immutable base ceiling plus the tenant
 * restriction child ({@code policy}; {@code null} means the tenant has no child yet and purely
 * inherits the base ceiling).
 *
 * <p>{@code bundleId} is a SHA-256 over the canonical bundle content (the canonical child YAML + a
 * base-ceiling fingerprint), so two snapshots with identical policy content have identical ids and a
 * one-cell change produces a different id — which is exactly what makes the review hash and the
 * staleness check trustworthy.
 *
 * @param bundleId        the content-addressed identity ({@code bundle-<sha256-prefix>})
 * @param policy          the tenant restriction child IR ({@code null} = base-only)
 * @param ceiling         the immutable base ceiling this bundle inherits from
 * @param canonicalContent the exact canonical bytes the id is derived from (kept for evidence)
 */
public record BundleSnapshot(String bundleId, PolicyIR policy, BaseCeiling ceiling, String canonicalContent) {

    /**
     * Build a snapshot from a validated child IR (or {@code null} for base-only) and the base ceiling,
     * deriving the content-addressed id from the canonical YAML the {@link CanonicalPolicyWriter}
     * materialises (never the model's raw text).
     */
    public static BundleSnapshot of(PolicyIR policy, BaseCeiling ceiling, CanonicalPolicyWriter writer) {
        String childYaml = policy == null ? "<base-only>\n" : writer.write(policy);
        String content = childYaml + "\n# base-ceiling:" + ceilingFingerprint(ceiling);
        String id = "bundle-" + StudioHashing.sha256Hex(content).substring(0, 16);
        return new BundleSnapshot(id, policy, ceiling, content);
    }

    /** A canonical, order-independent fingerprint of the immutable base ceiling. */
    private static String ceilingFingerprint(BaseCeiling ceiling) {
        String tuples = ceiling.tuples().stream()
                .map(t -> t.action() + "@" + t.role())
                .sorted()
                .reduce((a, b) -> a + "," + b)
                .orElse("");
        return ceiling.resourceKind()
                + "|backstop=" + ceiling.carriesTenantEqualityBackstop()
                + "|tuples=" + tuples;
    }
}
