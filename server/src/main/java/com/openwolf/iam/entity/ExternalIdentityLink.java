package com.openwolf.iam.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

import java.time.Instant;
import java.util.UUID;

@Entity
@Table(name = "external_identity_links")
public class ExternalIdentityLink {
    public enum Status { ACTIVE, DISABLED }

    @Id private UUID id;
    @Column(name = "tenant_id", nullable = false) private String tenantId;
    @Column(name = "source_id", nullable = false) private UUID sourceId;
    @Column(nullable = false) private String issuer;
    @Column(nullable = false) private String subject;
    @Column(name = "principal_id", nullable = false) private String principalId;
    @Enumerated(EnumType.STRING) @Column(nullable = false) private Status status;
    @Column(name = "created_at", nullable = false) private Instant createdAt;
    @Column(name = "updated_at", nullable = false) private Instant updatedAt;

    protected ExternalIdentityLink() {}
    public ExternalIdentityLink(String tenantId, UUID sourceId, String issuer, String subject, String principalId) {
        this.id = UUID.randomUUID(); this.tenantId = tenantId; this.sourceId = sourceId; this.issuer = issuer;
        this.subject = subject; this.principalId = principalId; this.status = Status.ACTIVE;
        this.createdAt = Instant.now(); this.updatedAt = createdAt;
    }
    public void disable() { status = Status.DISABLED; updatedAt = Instant.now(); }
    public UUID getId() { return id; } public String getTenantId() { return tenantId; }
    public UUID getSourceId() { return sourceId; } public String getIssuer() { return issuer; }
    public String getSubject() { return subject; } public String getPrincipalId() { return principalId; }
    public Status getStatus() { return status; } public Instant getCreatedAt() { return createdAt; }
    public Instant getUpdatedAt() { return updatedAt; }
}
