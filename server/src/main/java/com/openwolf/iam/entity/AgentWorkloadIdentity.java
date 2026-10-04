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
@Table(name = "agent_workload_identities")
public class AgentWorkloadIdentity {
    /** SUSPENDED is reversible; REVOKED and RETIRED are terminal (Phase 3.15). Only ACTIVE carries authority. */
    public enum Status { ACTIVE, SUSPENDED, REVOKED, RETIRED }

    @Id private UUID id;
    @Column(name = "tenant_id", nullable = false) private String tenantId;
    @Column(name = "workload_ref", nullable = false) private String workloadRef;
    @Column(nullable = false) private String name;
    @Column(name = "oauth_client_id", nullable = false) private String oauthClientId;
    @Enumerated(EnumType.STRING) @Column(nullable = false) private Status status;
    @Column(name = "created_at", nullable = false) private Instant createdAt;
    @Column(name = "revoked_at") private Instant revokedAt;
    @Version @Column(nullable = false) private long revision;
    @Column(name = "suspended_at") private Instant suspendedAt;
    @Column(name = "suspension_reason") private String suspensionReason;
    @Column(name = "retired_at") private Instant retiredAt;
    @Column(name = "owner_team_id") private UUID ownerTeamId;
    @Column(name = "accountable_principal_id") private String accountablePrincipalId;
    @Column(name = "ownership_assigned_at") private Instant ownershipAssignedAt;
    @Column(name = "last_reviewed_at") private Instant lastReviewedAt;

    protected AgentWorkloadIdentity() {}

    public AgentWorkloadIdentity(String tenantId, String workloadRef, String name,
                                 String oauthClientId, Instant now) {
        this.id = UUID.randomUUID();
        this.tenantId = tenantId;
        this.workloadRef = workloadRef;
        this.name = name;
        this.oauthClientId = oauthClientId;
        this.status = Status.ACTIVE;
        this.createdAt = now;
    }

    public void revoke(Instant now) {
        if (status == Status.REVOKED || status == Status.RETIRED) return;
        status = Status.REVOKED;
        revokedAt = now;
        suspendedAt = null;
    }

    /** Reversible stop (owner departure, review finding, administrator). Returns false if nothing changed. */
    public boolean suspend(String reason, Instant now) {
        if (status != Status.ACTIVE) return false;
        status = Status.SUSPENDED;
        suspendedAt = now;
        suspensionReason = reason;
        return true;
    }

    public boolean reactivate() {
        if (status != Status.SUSPENDED) return false;
        status = Status.ACTIVE;
        suspendedAt = null;
        suspensionReason = null;
        return true;
    }

    /** Terminal: the identity can never again obtain authority; its history is kept. */
    public boolean retire(Instant now) {
        if (status == Status.RETIRED || status == Status.REVOKED) return false;
        status = Status.RETIRED;
        retiredAt = now;
        suspendedAt = null;
        return true;
    }

    public void assignOwnership(UUID teamId, String accountablePrincipalId, Instant now) {
        this.ownerTeamId = teamId;
        this.accountablePrincipalId = accountablePrincipalId;
        this.ownershipAssignedAt = now;
    }

    public void reviewed(Instant now) { this.lastReviewedAt = now; }

    /** True once ownership has been assigned; from then on it is enforced on every use. */
    public boolean ownershipAssigned() { return ownershipAssignedAt != null; }

    public UUID getId() { return id; }
    public String getTenantId() { return tenantId; }
    public String getWorkloadRef() { return workloadRef; }
    public String getName() { return name; }
    public String getOauthClientId() { return oauthClientId; }
    public Status getStatus() { return status; }
    public Instant getCreatedAt() { return createdAt; }
    public Instant getRevokedAt() { return revokedAt; }
    public long getRevision() { return revision; }
    public Instant getSuspendedAt() { return suspendedAt; }
    public String getSuspensionReason() { return suspensionReason; }
    public Instant getRetiredAt() { return retiredAt; }
    public UUID getOwnerTeamId() { return ownerTeamId; }
    public String getAccountablePrincipalId() { return accountablePrincipalId; }
    public Instant getOwnershipAssignedAt() { return ownershipAssignedAt; }
    public Instant getLastReviewedAt() { return lastReviewedAt; }
}
