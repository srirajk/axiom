package com.openwolf.iam.authority.standing;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

/**
 * Phase 3.3 owner-approved standing (offline) authority for one Agent workload. Binding facts are immutable; status,
 * version and the renewal-handle digests change. {@code version} increases only when authority is withdrawn, so
 * tokens carry it and fail once it moves.
 */
@Entity
@Table(name = "standing_grants")
public class StandingGrant {
    public enum Status { APPROVED, ACTIVE, REVOKED }

    @Id private UUID id;
    @Column(name = "tenant_id", nullable = false) private String tenantId;
    @Column(name = "owner_principal_id", nullable = false) private String ownerPrincipalId;
    @Column(name = "owner_application_id", nullable = false) private UUID ownerApplicationId;
    @Column(name = "agent_workload_id", nullable = false) private UUID agentWorkloadId;
    @Column(name = "route_id", nullable = false) private UUID routeId;
    @Column(nullable = false) private String audience;
    @JdbcTypeCode(SqlTypes.JSON) @Column(nullable = false, columnDefinition = "jsonb") private List<String> scopes;
    @Column(nullable = false) private String purpose;
    @Column(name = "approved_at", nullable = false) private Instant approvedAt;
    @Column(name = "approved_auth_time", nullable = false) private Instant approvedAuthTime;
    @Column(name = "expires_at", nullable = false) private Instant expiresAt;
    @Enumerated(EnumType.STRING) @Column(nullable = false) private Status status;
    @Column(nullable = false) private long version;
    @Column(name = "handle_digest") private String handleDigest;
    @Column(name = "previous_handle_digest") private String previousHandleDigest;
    @Column(name = "handle_generation", nullable = false) private long handleGeneration;
    @Column(name = "claimed_at") private Instant claimedAt;
    @Column(name = "last_renewed_at") private Instant lastRenewedAt;
    @Column(name = "revoked_at") private Instant revokedAt;
    @Column(name = "revocation_reason") private String revocationReason;
    @Column(name = "created_at", nullable = false) private Instant createdAt;

    protected StandingGrant() {}

    StandingGrant(String tenantId, String owner, UUID ownerApplicationId, UUID agentWorkloadId, UUID routeId,
                  String audience, List<String> scopes, String purpose, Instant authTime, Instant expiresAt,
                  Instant now) {
        this.id = UUID.randomUUID();
        this.tenantId = tenantId;
        this.ownerPrincipalId = owner;
        this.ownerApplicationId = ownerApplicationId;
        this.agentWorkloadId = agentWorkloadId;
        this.routeId = routeId;
        this.audience = audience;
        this.scopes = List.copyOf(scopes);
        this.purpose = purpose;
        this.approvedAt = now;
        this.approvedAuthTime = authTime;
        this.expiresAt = expiresAt;
        this.status = Status.APPROVED;
        this.version = 1;
        this.createdAt = now;
    }

    /** First redemption by the bound workload, or a renewal; installs the digest of the next handle. */
    void rotate(String nextHandleDigest, Instant now) {
        if (status == Status.APPROVED) {
            status = Status.ACTIVE;
            claimedAt = now;
        }
        previousHandleDigest = handleDigest;
        handleDigest = nextHandleDigest;
        handleGeneration++;
        lastRenewedAt = now;
    }

    /** Withdrawal is permanent; the version moves so every outstanding token and task binding fails. */
    boolean revoke(String reason, Instant now) {
        if (status == Status.REVOKED) return false;
        status = Status.REVOKED;
        version++;
        revokedAt = now;
        revocationReason = reason;
        return true;
    }

    public UUID getId() { return id; }
    public String getTenantId() { return tenantId; }
    public String getOwnerPrincipalId() { return ownerPrincipalId; }
    public UUID getOwnerApplicationId() { return ownerApplicationId; }
    public UUID getAgentWorkloadId() { return agentWorkloadId; }
    public UUID getRouteId() { return routeId; }
    public String getAudience() { return audience; }
    public List<String> getScopes() { return scopes; }
    public String getPurpose() { return purpose; }
    public Instant getApprovedAt() { return approvedAt; }
    public Instant getApprovedAuthTime() { return approvedAuthTime; }
    public Instant getExpiresAt() { return expiresAt; }
    public Status getStatus() { return status; }
    public long getVersion() { return version; }
    String getHandleDigest() { return handleDigest; }
    String getPreviousHandleDigest() { return previousHandleDigest; }
    public long getHandleGeneration() { return handleGeneration; }
    public Instant getClaimedAt() { return claimedAt; }
    public Instant getLastRenewedAt() { return lastRenewedAt; }
    public Instant getRevokedAt() { return revokedAt; }
    public String getRevocationReason() { return revocationReason; }
    public Instant getCreatedAt() { return createdAt; }
}
