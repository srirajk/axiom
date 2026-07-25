package com.openwolf.iam.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import jakarta.persistence.Version;

import java.time.Instant;
import java.util.UUID;

@Entity
@Table(name = "scim_provisioning_sources")
public class ScimProvisioningSource {
    public enum Status { ACTIVE, REVOKED }

    @Id private UUID id;
    @Column(name = "tenant_id", nullable = false) private String tenantId;
    @Column(name = "identity_source_id") private UUID identitySourceId;
    @Column(name = "display_name", nullable = false) private String displayName;
    @Column(nullable = false, unique = true) private String selector;
    @Column(name = "secret_hash", nullable = false) private String secretHash;
    @Enumerated(EnumType.STRING) @Column(nullable = false) private Status status;
    @Version @Column(nullable = false) private long revision;
    @Column(name = "created_at", nullable = false) private Instant createdAt;
    @Column(name = "updated_at", nullable = false) private Instant updatedAt;

    protected ScimProvisioningSource() {}

    public ScimProvisioningSource(String tenantId, UUID identitySourceId, String displayName,
                                   String selector, String secretHash) {
        this.id = UUID.randomUUID(); this.tenantId = tenantId; this.identitySourceId = identitySourceId;
        this.displayName = displayName; this.selector = selector; this.secretHash = secretHash;
        this.status = Status.ACTIVE; this.revision = 1; this.createdAt = Instant.now(); this.updatedAt = createdAt;
    }

    public void rotate(String selector, String secretHash) {
        this.selector = selector; this.secretHash = secretHash; this.status = Status.ACTIVE;
        this.updatedAt = Instant.now();
    }
    public void revoke() { this.status = Status.REVOKED; this.updatedAt = Instant.now(); }
    public UUID getId() { return id; }
    public String getTenantId() { return tenantId; }
    public UUID getIdentitySourceId() { return identitySourceId; }
    public String getDisplayName() { return displayName; }
    public String getSelector() { return selector; }
    public String getSecretHash() { return secretHash; }
    public Status getStatus() { return status; }
    public long getRevision() { return revision; }
    public Instant getCreatedAt() { return createdAt; }
    public Instant getUpdatedAt() { return updatedAt; }
}
