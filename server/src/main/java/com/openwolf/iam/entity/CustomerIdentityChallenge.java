package com.openwolf.iam.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

import java.time.Instant;
import java.util.UUID;

@Entity
@Table(name = "customer_identity_challenges")
public class CustomerIdentityChallenge {
    public enum Type { EMAIL_VERIFICATION, PASSWORD_RECOVERY }

    @Id private UUID id;
    @Column(name = "tenant_id", nullable = false) private String tenantId;
    @Column(name = "customer_id", nullable = false) private UUID customerId;
    @Enumerated(EnumType.STRING) @Column(name = "challenge_type", nullable = false) private Type type;
    @Column(name = "token_hash", nullable = false) private String tokenHash;
    @Column(name = "expires_at", nullable = false) private Instant expiresAt;
    @Column(name = "used_at") private Instant usedAt;
    @Column(name = "created_at", nullable = false) private Instant createdAt;

    protected CustomerIdentityChallenge() {}

    public CustomerIdentityChallenge(String tenantId, UUID customerId, Type type,
                                     String tokenHash, Instant expiresAt, Instant now) {
        this.id = UUID.randomUUID();
        this.tenantId = tenantId;
        this.customerId = customerId;
        this.type = type;
        this.tokenHash = tokenHash;
        this.expiresAt = expiresAt;
        this.createdAt = now;
    }

    public void consume(Instant now) {
        if (usedAt != null) throw new IllegalStateException("challenge was already used");
        if (!expiresAt.isAfter(now)) throw new IllegalStateException("challenge has expired");
        usedAt = now;
    }

    public void invalidate(Instant now) {
        if (usedAt == null) usedAt = now;
    }

    public UUID getId() { return id; }
    public String getTenantId() { return tenantId; }
    public UUID getCustomerId() { return customerId; }
    public Type getType() { return type; }
    public String getTokenHash() { return tokenHash; }
    public Instant getExpiresAt() { return expiresAt; }
    public Instant getUsedAt() { return usedAt; }
    public Instant getCreatedAt() { return createdAt; }
}
