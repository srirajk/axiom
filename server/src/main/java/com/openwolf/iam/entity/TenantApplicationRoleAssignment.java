package com.openwolf.iam.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

import java.time.Instant;
import java.util.UUID;

@Entity
@Table(name = "tenant_application_role_assignments")
public class TenantApplicationRoleAssignment {
    @Id private UUID id;
    @Column(name = "membership_id", nullable = false) private UUID membershipId;
    @Column(name = "application_role_id", nullable = false) private UUID applicationRoleId;
    @Column(name = "assignment_source", nullable = false) private String assignmentSource;
    @Column(name = "assigned_by", nullable = false) private String assignedBy;
    @Column(name = "created_at", nullable = false) private Instant createdAt;
    @Column(name = "revoked_at") private Instant revokedAt;

    protected TenantApplicationRoleAssignment() {}

    public TenantApplicationRoleAssignment(UUID membershipId, UUID applicationRoleId,
                                           String assignmentSource, String assignedBy) {
        this.id = UUID.randomUUID();
        this.membershipId = membershipId;
        this.applicationRoleId = applicationRoleId;
        this.assignmentSource = assignmentSource;
        this.assignedBy = assignedBy;
        this.createdAt = Instant.now();
    }

    public void revoke() { if (revokedAt == null) revokedAt = Instant.now(); }
    public UUID getId() { return id; }
    public UUID getMembershipId() { return membershipId; }
    public UUID getApplicationRoleId() { return applicationRoleId; }
    public String getAssignmentSource() { return assignmentSource; }
    public String getAssignedBy() { return assignedBy; }
    public Instant getCreatedAt() { return createdAt; }
    public Instant getRevokedAt() { return revokedAt; }
}
