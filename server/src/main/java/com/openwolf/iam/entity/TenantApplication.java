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
@Table(name = "tenant_applications")
public class TenantApplication {
    public enum Status { ACTIVE, DISABLED }

    @Id private UUID id;
    @Column(name = "tenant_id", nullable = false) private String tenantId;
    @Column(name = "application_key", nullable = false) private String applicationKey;
    @Column(name = "display_name", nullable = false) private String displayName;
    private String description;
    @Column(nullable = false) private String audience;
    @Enumerated(EnumType.STRING) @Column(nullable = false) private Status status;
    @Version @Column(nullable = false) private long revision;
    @Column(name = "created_at", nullable = false) private Instant createdAt;
    @Column(name = "updated_at", nullable = false) private Instant updatedAt;

    protected TenantApplication() {}
    public TenantApplication(String tenantId, String applicationKey, String displayName, String description, String audience) {
        this.id = UUID.randomUUID(); this.tenantId = tenantId; this.applicationKey = applicationKey;
        this.displayName = displayName; this.description = description; this.audience = audience;
        this.status = Status.ACTIVE; this.revision = 1; this.createdAt = Instant.now(); this.updatedAt = this.createdAt;
    }
    public void disable() { status = Status.DISABLED; updatedAt = Instant.now(); }
    public UUID getId() { return id; } public String getTenantId() { return tenantId; }
    public String getApplicationKey() { return applicationKey; } public String getDisplayName() { return displayName; }
    public String getDescription() { return description; } public String getAudience() { return audience; }
    public Status getStatus() { return status; } public long getRevision() { return revision; }
    public Instant getCreatedAt() { return createdAt; } public Instant getUpdatedAt() { return updatedAt; }
}
