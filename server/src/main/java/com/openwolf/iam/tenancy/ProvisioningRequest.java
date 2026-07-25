package com.openwolf.iam.tenancy;

/**
 * A request to provision a tenant (Axiom B4). The tenant id is the canonical, DNS-safe identifier
 * (same grammar as {@code TenantClaims}); name and slug are display metadata.
 */
public record ProvisioningRequest(String tenantId, String name, String slug) {

    public ProvisioningRequest {
        if (tenantId == null || tenantId.isBlank()) {
            throw new IllegalArgumentException("tenantId is required");
        }
        if (name == null || name.isBlank()) {
            name = tenantId;
        }
        if (slug == null || slug.isBlank()) {
            slug = tenantId;
        }
    }
}
