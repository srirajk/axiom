package com.openwolf.iam.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import jakarta.persistence.Version;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

@Entity
@Table(name = "agent_exchange_routes")
public class AgentExchangeRoute {
    public enum DestinationType { AGENT, RESOURCE, GATEWAY }
    public enum Status { ACTIVE, REVOKED }

    @Id private UUID id;
    @Column(name = "tenant_id", nullable = false) private String tenantId;
    @Column(name = "source_workload_id", nullable = false) private UUID sourceWorkloadId;
    @Enumerated(EnumType.STRING) @Column(name = "destination_type", nullable = false)
    private DestinationType destinationType;
    @Column(name = "destination_workload_id") private UUID destinationWorkloadId;
    @Column(nullable = false) private String audience;
    @JdbcTypeCode(SqlTypes.JSON)
    @Column(name = "allowed_scopes", nullable = false, columnDefinition = "jsonb")
    private List<String> allowedScopes = new ArrayList<>();
    @Column(nullable = false) private String purpose;
    @Enumerated(EnumType.STRING) @Column(nullable = false) private Status status;
    @Column(name = "created_at", nullable = false) private Instant createdAt;
    @Column(name = "expires_at", nullable = false) private Instant expiresAt;
    @Column(name = "revoked_at") private Instant revokedAt;
    @Version @Column(nullable = false) private long revision;

    protected AgentExchangeRoute() {}

    public AgentExchangeRoute(String tenantId, UUID sourceWorkloadId, DestinationType destinationType,
                              UUID destinationWorkloadId, String audience, List<String> allowedScopes,
                              String purpose, Instant expiresAt, Instant now) {
        this.id = UUID.randomUUID();
        this.tenantId = tenantId;
        this.sourceWorkloadId = sourceWorkloadId;
        this.destinationType = destinationType;
        this.destinationWorkloadId = destinationWorkloadId;
        this.audience = audience;
        this.allowedScopes = new ArrayList<>(allowedScopes);
        this.purpose = purpose;
        this.status = Status.ACTIVE;
        this.createdAt = now;
        this.expiresAt = expiresAt;
    }

    public void revoke(Instant now) {
        if (status == Status.REVOKED) return;
        status = Status.REVOKED;
        revokedAt = now;
    }

    public boolean usableAt(Instant now) { return status == Status.ACTIVE && expiresAt.isAfter(now); }
    public UUID getId() { return id; }
    public String getTenantId() { return tenantId; }
    public UUID getSourceWorkloadId() { return sourceWorkloadId; }
    public DestinationType getDestinationType() { return destinationType; }
    public UUID getDestinationWorkloadId() { return destinationWorkloadId; }
    public String getAudience() { return audience; }
    public List<String> getAllowedScopes() { return List.copyOf(allowedScopes); }
    public String getPurpose() { return purpose; }
    public Status getStatus() { return status; }
    public Instant getCreatedAt() { return createdAt; }
    public Instant getExpiresAt() { return expiresAt; }
    public Instant getRevokedAt() { return revokedAt; }
    public long getRevision() { return revision; }
}
