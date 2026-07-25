package com.openwolf.iam.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

import java.time.Instant;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;

@Entity
@Table(name = "tenant_application_memberships")
public class TenantApplicationMembership {
    public enum Status { ACTIVE, DISABLED }

    @Id private UUID id;
    @Column(name = "application_id", nullable = false) private UUID applicationId;
    @Column(name = "principal_id", nullable = false) private String principalId;
    @Enumerated(EnumType.STRING) @Column(nullable = false) private Status status;
    @JdbcTypeCode(SqlTypes.JSON) @Column(nullable = false, columnDefinition = "jsonb")
    private Map<String, Object> attributes = new LinkedHashMap<>();
    @Column(name = "assignment_source", nullable = false) private String assignmentSource;
    @Column(name = "assigned_by", nullable = false) private String assignedBy;
    @Column(name = "entitlement_revision", nullable = false) private long entitlementRevision;
    @Column(name = "created_at", nullable = false) private Instant createdAt;
    @Column(name = "updated_at", nullable = false) private Instant updatedAt;

    protected TenantApplicationMembership() {}

    public TenantApplicationMembership(UUID applicationId, String principalId, String assignmentSource,
                                       String assignedBy) {
        this.id = UUID.randomUUID();
        this.applicationId = applicationId;
        this.principalId = principalId;
        this.status = Status.ACTIVE;
        this.attributes = new LinkedHashMap<>();
        this.assignmentSource = assignmentSource;
        this.assignedBy = assignedBy;
        this.entitlementRevision = 1;
        this.createdAt = Instant.now();
        this.updatedAt = createdAt;
    }

    public void replaceAttributes(Map<String, Object> value) {
        attributes = new LinkedHashMap<>(value);
        touch();
    }

    public void touch() {
        entitlementRevision += 1;
        updatedAt = Instant.now();
    }

    public void disable() {
        if (status == Status.ACTIVE) {
            status = Status.DISABLED;
            touch();
        }
    }

    public void enable() {
        if (status == Status.DISABLED) {
            status = Status.ACTIVE;
            touch();
        }
    }

    public UUID getId() { return id; }
    public UUID getApplicationId() { return applicationId; }
    public String getPrincipalId() { return principalId; }
    public Status getStatus() { return status; }
    public Map<String, Object> getAttributes() { return Collections.unmodifiableMap(new LinkedHashMap<>(attributes)); }
    public String getAssignmentSource() { return assignmentSource; }
    public String getAssignedBy() { return assignedBy; }
    public long getEntitlementRevision() { return entitlementRevision; }
    public Instant getCreatedAt() { return createdAt; }
    public Instant getUpdatedAt() { return updatedAt; }
}
