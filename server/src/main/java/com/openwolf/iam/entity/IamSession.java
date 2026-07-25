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

/** Durable index for a token session; it contains no bearer token material. */
@Entity
@Table(name = "iam_sessions")
public class IamSession {
    public enum Status { ACTIVE, REVOKED, EXPIRED }

    @Id private UUID id;
    @Column(name = "tenant_id", nullable = false) private String tenantId;
    @Column(name = "principal_id", nullable = false) private String principalId;
    @Column(name = "application_id") private UUID applicationId;
    @Column(name = "client_id", nullable = false) private String clientId;
    @Column(name = "issued_at", nullable = false) private Instant issuedAt;
    @Column(name = "last_seen_at", nullable = false) private Instant lastSeenAt;
    @Column(name = "expires_at", nullable = false) private Instant expiresAt;
    @Enumerated(EnumType.STRING) @Column(nullable = false) private Status status;
    @Column(name = "recovery_marked", nullable = false) private boolean recoveryMarked;
    @Column(name = "recovery_scope") private String recoveryScope;
    @Column(name = "recovery_operator_a") private UUID recoveryOperatorA;
    @Column(name = "recovery_operator_b") private UUID recoveryOperatorB;
    @Version @Column(nullable = false) private long revision;

    protected IamSession() {}

    public IamSession(UUID id, String tenantId, String principalId, UUID applicationId, String clientId,
                      Instant issuedAt, Instant expiresAt) {
        this.id = id;
        this.tenantId = tenantId;
        this.principalId = principalId;
        this.applicationId = applicationId;
        this.clientId = clientId;
        this.issuedAt = issuedAt;
        this.lastSeenAt = issuedAt;
        this.expiresAt = expiresAt;
        this.status = Status.ACTIVE;
        this.recoveryMarked = false;
        this.revision = 1;
    }

    public IamSession(UUID id, String tenantId, String principalId, String clientId,
                      Instant issuedAt, Instant expiresAt, String recoveryScope,
                      UUID recoveryOperatorA, UUID recoveryOperatorB) {
        this.id = id; this.tenantId = tenantId; this.principalId = principalId;
        this.clientId = clientId; this.issuedAt = issuedAt; this.lastSeenAt = issuedAt;
        this.expiresAt = expiresAt; this.status = Status.ACTIVE; this.recoveryMarked = true;
        this.recoveryScope = recoveryScope; this.recoveryOperatorA = recoveryOperatorA;
        this.recoveryOperatorB = recoveryOperatorB; this.revision = 1;
    }

    public void revoke() { status = Status.REVOKED; }
    public void expire() { status = Status.EXPIRED; }
    public UUID getId() { return id; }
    public String getTenantId() { return tenantId; }
    public String getPrincipalId() { return principalId; }
    public UUID getApplicationId() { return applicationId; }
    public String getClientId() { return clientId; }
    public Instant getIssuedAt() { return issuedAt; }
    public Instant getLastSeenAt() { return lastSeenAt; }
    public Instant getExpiresAt() { return expiresAt; }
    public Status getStatus() { return status; }
    public boolean isRecoveryMarked() { return recoveryMarked; }
    public String getRecoveryScope() { return recoveryScope; }
    public UUID getRecoveryOperatorA() { return recoveryOperatorA; }
    public UUID getRecoveryOperatorB() { return recoveryOperatorB; }
    public long getRevision() { return revision; }
}
