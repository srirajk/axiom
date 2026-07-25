package com.openwolf.iam.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import jakarta.persistence.Version;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

import java.time.Instant;
import java.util.UUID;

@Entity
@Table(name = "scim_resource_links")
public class ScimResourceLink {
    @Id private UUID id;
    @Column(name = "source_id", nullable = false) private UUID sourceId;
    @Column(name = "tenant_id", nullable = false) private String tenantId;
    @Column(name = "resource_type", nullable = false) private String resourceType;
    @Column(name = "external_id", nullable = false) private String externalId;
    @Column(name = "resource_id", nullable = false) private String resourceId;
    @Column(nullable = false) private long version;
    @JdbcTypeCode(SqlTypes.JSON) @Column(name = "managed_fields", nullable = false, columnDefinition = "jsonb") private String managedFields;
    @Column(name = "created_at", nullable = false) private Instant createdAt;
    @Column(name = "updated_at", nullable = false) private Instant updatedAt;
    @Version @Column(name = "row_version", nullable = false) private long rowVersion;

    protected ScimResourceLink() {}
    public ScimResourceLink(UUID sourceId, String tenantId, String resourceType, String externalId,
                            String resourceId, String managedFields) {
        this.id = UUID.randomUUID(); this.sourceId = sourceId; this.tenantId = tenantId;
        this.resourceType = resourceType; this.externalId = externalId; this.resourceId = resourceId;
        this.version = 1; this.managedFields = managedFields; this.createdAt = Instant.now(); this.updatedAt = createdAt;
    }
    public void bump(String managedFields) { this.version++; this.managedFields = managedFields; this.updatedAt = Instant.now(); }
    public UUID getId() { return id; }
    public UUID getSourceId() { return sourceId; }
    public String getTenantId() { return tenantId; }
    public String getResourceType() { return resourceType; }
    public String getExternalId() { return externalId; }
    public String getResourceId() { return resourceId; }
    public long getVersion() { return version; }
    public String getManagedFields() { return managedFields; }
    public Instant getCreatedAt() { return createdAt; }
    public Instant getUpdatedAt() { return updatedAt; }
}
