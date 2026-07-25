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
@Table(name = "recovery_operators")
public class RecoveryOperator {
    public enum Status { PENDING_ACTIVATION, ACTIVE, PENDING_ROTATION, DISABLED }

    @Id private UUID id;
    @Column(name = "tenant_id", nullable = false) private String tenantId;
    @Column(name = "principal_id", nullable = false) private String principalId;
    @Column(name = "credential_hash") private String credentialHash;
    @Enumerated(EnumType.STRING) @Column(nullable = false) private Status status;
    @Column(name = "created_at", nullable = false) private Instant createdAt;
    @Column(name = "updated_at", nullable = false) private Instant updatedAt;
    @Column(name = "initiator_principal_id") private String initiatorPrincipalId;
    @Column(name = "activation_actor_id") private String activationActorId;
    @Column(name = "activation_at") private Instant activationAt;
    @Version @Column(nullable = false) private long revision;

    protected RecoveryOperator() {}

    public RecoveryOperator(String tenantId, String principalId, String credentialHash, Instant now) {
        this.id = UUID.randomUUID(); this.tenantId = tenantId; this.principalId = principalId;
        this.credentialHash = credentialHash; this.status = Status.ACTIVE;
        this.createdAt = now; this.updatedAt = now; this.revision = 1;
    }

    public static RecoveryOperator pending(String tenantId, String principalId, String initiatorPrincipalId, Instant now) {
        return new RecoveryOperator(tenantId, principalId, initiatorPrincipalId, now, true);
    }

    private RecoveryOperator(String tenantId, String principalId, String initiatorPrincipalId, Instant now, boolean pending) {
        this.id = UUID.randomUUID(); this.tenantId = tenantId; this.principalId = principalId;
        this.initiatorPrincipalId = initiatorPrincipalId; this.status = Status.PENDING_ACTIVATION;
        this.createdAt = now; this.updatedAt = now; this.revision = 1;
    }

    public void beginRotation(String initiatorPrincipalId, Instant now) {
        if (status != Status.ACTIVE) throw new IllegalStateException("recovery operator is not active");
        this.credentialHash = null; this.initiatorPrincipalId = initiatorPrincipalId; this.activationActorId = null;
        this.activationAt = null; this.status = Status.PENDING_ROTATION; this.updatedAt = now;
    }

    public void beginActivation(String initiatorPrincipalId, Instant now) {
        if (status != Status.DISABLED) throw new IllegalStateException("recovery operator is not disabled");
        this.credentialHash = null; this.initiatorPrincipalId = initiatorPrincipalId;
        this.activationActorId = null; this.activationAt = null;
        this.status = Status.PENDING_ACTIVATION; this.updatedAt = now;
    }

    public void disable(Instant now) { this.status = Status.DISABLED; this.updatedAt = now; }
    public void activate(String credentialHash, String actorId, Instant now) {
        if (status != Status.PENDING_ACTIVATION && status != Status.PENDING_ROTATION) {
            throw new IllegalStateException("recovery operator is not pending activation");
        }
        if (actorId == null || actorId.equals(initiatorPrincipalId)) {
            throw new IllegalStateException("recovery activation requires a distinct actor");
        }
        this.credentialHash = credentialHash; this.status = Status.ACTIVE;
        this.activationActorId = actorId; this.activationAt = now; this.updatedAt = now;
    }
    public UUID getId() { return id; }
    public String getTenantId() { return tenantId; }
    public String getPrincipalId() { return principalId; }
    public String getCredentialHash() { return credentialHash; }
    public Status getStatus() { return status; }
    public Instant getCreatedAt() { return createdAt; }
    public Instant getUpdatedAt() { return updatedAt; }
    public String getInitiatorPrincipalId() { return initiatorPrincipalId; }
    public String getActivationActorId() { return activationActorId; }
    public Instant getActivationAt() { return activationAt; }
    public long getRevision() { return revision; }
}
