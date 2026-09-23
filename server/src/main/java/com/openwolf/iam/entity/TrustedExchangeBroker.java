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
@Table(name = "trusted_exchange_brokers")
public class TrustedExchangeBroker {
    public enum Status { ACTIVE, REVOKED }

    @Id private UUID id;
    @Column(name = "tenant_id", nullable = false) private String tenantId;
    @Column(name = "oauth_client_id", nullable = false) private String oauthClientId;
    @Column(name = "gateway_audience", nullable = false) private String gatewayAudience;
    @JdbcTypeCode(SqlTypes.JSON)
    @Column(name = "allowed_scopes", nullable = false, columnDefinition = "jsonb")
    private List<String> allowedScopes = new ArrayList<>();
    @Enumerated(EnumType.STRING) @Column(nullable = false) private Status status;
    @Column(name = "created_at", nullable = false) private Instant createdAt;
    @Column(name = "revoked_at") private Instant revokedAt;
    @Version @Column(nullable = false) private long revision;

    protected TrustedExchangeBroker() {}

    public TrustedExchangeBroker(String tenantId, String oauthClientId, String gatewayAudience,
                                 List<String> allowedScopes, Instant now) {
        this.id = UUID.randomUUID();
        this.tenantId = tenantId;
        this.oauthClientId = oauthClientId;
        this.gatewayAudience = gatewayAudience;
        this.allowedScopes = new ArrayList<>(allowedScopes);
        this.status = Status.ACTIVE;
        this.createdAt = now;
    }

    public void revoke(Instant now) {
        if (status == Status.REVOKED) return;
        status = Status.REVOKED;
        revokedAt = now;
    }

    public UUID getId() { return id; }
    public String getTenantId() { return tenantId; }
    public String getOauthClientId() { return oauthClientId; }
    public String getGatewayAudience() { return gatewayAudience; }
    public List<String> getAllowedScopes() { return List.copyOf(allowedScopes); }
    public Status getStatus() { return status; }
    public Instant getCreatedAt() { return createdAt; }
    public Instant getRevokedAt() { return revokedAt; }
    public long getRevision() { return revision; }
}
