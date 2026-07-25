package com.openwolf.iam.tenancy;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

import java.time.Instant;
import java.util.Objects;

/**
 * A tenant that is <b>fully provisioned and visible</b> (Axiom B4). Membership of this table IS the
 * active directory: a tenant is written here only by the activation compare-and-set, after all four
 * artifacts are verified, and is removed FIRST on deprovision. The gateway's provisioned-tenant
 * snapshot (A2) is a read replica of this set; a tenant absent here resolves as unknown and fails
 * closed at the gateway with zero I/O.
 *
 * <p>{@code ddl-auto: validate} — columns MUST match {@code V10__tenant_provisioning.sql}.
 */
@Entity
@Table(name = "active_tenants")
public class ActiveTenant {

    @Id
    @Column(name = "tenant_id")
    private String tenantId;

    @Column(name = "policy_version", nullable = false)
    private String policyVersion;

    @Column(name = "directory_version", nullable = false)
    private long directoryVersion;

    @Column(name = "activated_at", nullable = false)
    private Instant activatedAt;

    protected ActiveTenant() {}

    public ActiveTenant(String tenantId, String policyVersion, long directoryVersion) {
        this.tenantId = tenantId;
        this.policyVersion = policyVersion;
        this.directoryVersion = directoryVersion;
        this.activatedAt = Instant.now();
    }

    public String getTenantId() { return tenantId; }
    public String getPolicyVersion() { return policyVersion; }
    public long getDirectoryVersion() { return directoryVersion; }
    public Instant getActivatedAt() { return activatedAt; }

    @Override
    public boolean equals(Object o) {
        return o instanceof ActiveTenant t && Objects.equals(tenantId, t.tenantId);
    }

    @Override
    public int hashCode() {
        return Objects.hash(tenantId);
    }
}
