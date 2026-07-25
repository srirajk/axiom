package com.openwolf.iam.tenancy;

/**
 * The Redis-namespace artifact of tenant provisioning (Axiom B4, A3/A4). A provisioned tenant gets
 * its own key namespace {@code t:{tenant}:} and per-tenant routing index {@code intent_idx__{tenant}}
 * (the exact grammar used by Axiom). This is a separate bounded context, so the real implementation is a control-plane
 * call across that seam; provisioning only orchestrates it and records that it was done.
 */
public interface TenantNamespaceAdapter {

    /** Create (idempotently) the tenant's Redis namespace + per-tenant index; return the key prefix. */
    String createNamespace(String tenantId);

    boolean namespaceExists(String tenantId);

    /** Remove non-audit Redis artifacts on deprovision — only AFTER the directory-version ack. */
    void removeNamespace(String tenantId);
}
