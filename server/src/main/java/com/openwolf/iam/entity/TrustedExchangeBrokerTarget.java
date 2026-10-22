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
@Table(name = "trusted_exchange_broker_targets")
public class TrustedExchangeBrokerTarget {
    public enum Status { ACTIVE, REVOKED }

    @Id private UUID id;
    @Column(name = "broker_id", nullable = false) private UUID brokerId;
    @Column(name = "tenant_id", nullable = false) private String tenantId;
    @Column(nullable = false) private String audience;
    @Enumerated(EnumType.STRING) @Column(name = "destination_type", nullable = false)
    private AgentExchangeRoute.DestinationType destinationType;
    @Column(name = "destination_workload_id") private UUID destinationWorkloadId;
    @JdbcTypeCode(SqlTypes.JSON)
    @Column(name = "allowed_scopes", nullable = false, columnDefinition = "jsonb")
    private List<String> allowedScopes = new ArrayList<>();
    @Column(nullable = false) private String purpose;
    @Enumerated(EnumType.STRING) @Column(nullable = false) private Status status;
    @Column(name = "created_at", nullable = false) private Instant createdAt;
    @Column(name = "revoked_at") private Instant revokedAt;
    @Version @Column(nullable = false) private long revision;

    protected TrustedExchangeBrokerTarget() {}

    public TrustedExchangeBrokerTarget(UUID brokerId, String tenantId, String audience,
                                       AgentExchangeRoute.DestinationType destinationType,
                                       UUID destinationWorkloadId, List<String> allowedScopes,
                                       String purpose, Instant now) {
        this.id = UUID.randomUUID();
        this.brokerId = brokerId;
        this.tenantId = tenantId;
        this.audience = audience;
        this.destinationType = destinationType;
        this.destinationWorkloadId = destinationWorkloadId;
        this.allowedScopes = new ArrayList<>(allowedScopes);
        this.purpose = purpose;
        this.status = Status.ACTIVE;
        this.createdAt = now;
    }

    public void revoke(Instant now) {
        if (status == Status.REVOKED) return;
        status = Status.REVOKED;
        revokedAt = now;
    }

    public UUID getId() { return id; }
    public UUID getBrokerId() { return brokerId; }
    public String getTenantId() { return tenantId; }
    public String getAudience() { return audience; }
    public AgentExchangeRoute.DestinationType getDestinationType() { return destinationType; }
    public UUID getDestinationWorkloadId() { return destinationWorkloadId; }
    public List<String> getAllowedScopes() { return List.copyOf(allowedScopes); }
    public String getPurpose() { return purpose; }
    public Status getStatus() { return status; }
    public Instant getCreatedAt() { return createdAt; }
    public Instant getRevokedAt() { return revokedAt; }
    public long getRevision() { return revision; }
}
