package com.openwolf.iam.tenancy;

/**
 * The Cerbos artifact of tenant provisioning (Axiom B4): build a NEW tenant-specific full bootstrap
 * bundle from the current approved base ceiling + B1's deny-all child policies, assign a new
 * content-addressed {@code b_*} policy version, STAGE it alongside the existing versions, and PROBE it.
 * The result is a normal C5 {@link com.openwolf.iam.policystudio.lifecycle.PolicyBundle}, not a separate
 * bootstrap-only version namespace. It NEVER
 * mutates the current live bundle and NEVER writes an empty scope policy (an empty tenant child is
 * fail-open under parental-consent inheritance — B1).
 */
public interface PolicyBootstrapAdapter {

    /**
     * Build and stage the deny-all bootstrap bundle for {@code tenantId}. Idempotent: because the
     * version is content-addressed, re-staging the same tenant re-writes byte-identical files under
     * the same version directory (no conflicting artifact).
     */
    TenantBootstrapBundle stage(String tenantId);

    /**
     * Compile the staged bundle together with the immutable base bundle using the pinned Cerbos, in
     * an ephemeral {@code docker run --rm} (or a local pinned binary) that never touches the running
     * PDP. Throws {@link ProvisioningException} if Cerbos is available and rejects the bundle. When
     * Cerbos is unavailable the deterministic totality of the deny-all children is the verification
     * and this is a logged no-op (see {@link #isProbeAvailable()}).
     */
    void probe(TenantBootstrapBundle bundle);

    /** True iff a pinned Cerbos (binary or docker image) is usable to run the compile probe. */
    boolean isProbeAvailable();

    /**
     * Deprovision retains policy bundles for the evidence-retention period — this is a no-op marker
     * that the staged bundle is NOT deleted on cleanup (it is evidence of what the tenant could do).
     */
    default void retainForEvidence(TenantBootstrapBundle bundle) {
        // intentionally empty: staged bundles are retained, never cleaned up
    }

    /**
     * Compensation for a FAILED provision (H6): discard the bundle that was staged during a run that
     * never activated, so a failure-after-N leaves no orphaned staged policy artifact on disk. This is
     * NOT deprovision retention ({@link #retainForEvidence}) — that retains the bundle of a tenant that
     * DID go live; a never-activated staging directory is debris, not evidence. Idempotent and
     * best-effort. Default no-op for adapters that stage nothing durable.
     */
    default void discardStaged(TenantBootstrapBundle bundle) {
        // intentionally empty: nothing durable to clean for a non-disk adapter
    }
}
