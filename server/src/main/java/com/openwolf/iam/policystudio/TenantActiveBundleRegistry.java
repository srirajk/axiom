package com.openwolf.iam.policystudio;

/**
 * The authority for a tenant's currently-active (live) policy bundle (Axiom Story C4). The consequence
 * review captures the current bundle id at generation time; at approval time the gate re-reads this
 * registry — if the tenant's active bundle has changed since the diff was generated, the approval is
 * BLOCKED until a fresh diff is computed against the new current bundle (C4.5, no stale diff).
 *
 * <p>The gateway never swaps this pointer to compute a diff; the diff runs against captured immutable
 * snapshots. This registry is read to detect drift, and written only by the deterministic promotion
 * path (out of scope here).
 */
public interface TenantActiveBundleRegistry {

    /** The id of the tenant's currently-active bundle, or {@code null} if the tenant has no active bundle. */
    String activeBundleId(String tenantId);
}
