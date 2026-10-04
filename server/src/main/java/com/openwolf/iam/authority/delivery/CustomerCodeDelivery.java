package com.openwolf.iam.authority.delivery;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

import java.time.Instant;
import java.util.UUID;

/** Durable delivery state for one customer code (Phase 3.1). Mutated only through conditional repository updates. */
@Entity
@Table(name = "customer_code_deliveries")
public class CustomerCodeDelivery {
    public enum Status { PENDING, SENT, ABANDONED }

    @Id private UUID id;
    @Column(name = "tenant_id", nullable = false) private String tenantId;
    @Column(name = "customer_id", nullable = false) private UUID customerId;
    @Column(name = "challenge_id", nullable = false) private UUID challengeId;
    @Enumerated(EnumType.STRING) @Column(nullable = false) private CustomerCodeDeliveryProvider.Channel channel;
    @Enumerated(EnumType.STRING) @Column(nullable = false) private CustomerCodeDeliveryProvider.Purpose purpose;
    @Column(name = "destination_digest", nullable = false) private String destinationDigest;
    @Column(name = "protected_code") private String protectedCode;
    @Enumerated(EnumType.STRING) @Column(nullable = false) private Status status;
    @Column(nullable = false) private int attempts;
    @Column(name = "max_attempts", nullable = false) private int maxAttempts;
    @Column(name = "next_attempt_at", nullable = false) private Instant nextAttemptAt;
    @Column(name = "lease_until") private Instant leaseUntil;
    @Column(name = "expires_at", nullable = false) private Instant expiresAt;
    @Column private String provider;
    @Column(name = "provider_message_ref") private String providerMessageRef;
    @Column(name = "last_failure") private String lastFailure;
    @Column(name = "created_at", nullable = false) private Instant createdAt;
    @Column(name = "updated_at", nullable = false) private Instant updatedAt;
    @Column(name = "sent_at") private Instant sentAt;

    protected CustomerCodeDelivery() {}

    CustomerCodeDelivery(String tenantId, UUID customerId, UUID challengeId, CustomerCodeDeliveryProvider.Purpose purpose,
                         String destinationDigest, String protectedCode, int maxAttempts, Instant expiresAt,
                         Instant now) {
        this.id = UUID.randomUUID();
        this.tenantId = tenantId;
        this.customerId = customerId;
        this.challengeId = challengeId;
        this.channel = CustomerCodeDeliveryProvider.Channel.EMAIL;
        this.purpose = purpose;
        this.destinationDigest = destinationDigest;
        this.protectedCode = protectedCode;
        this.status = Status.PENDING;
        this.maxAttempts = maxAttempts;
        this.nextAttemptAt = now;
        this.expiresAt = expiresAt;
        this.createdAt = now;
        this.updatedAt = now;
    }

    public UUID getId() { return id; }
    public String getTenantId() { return tenantId; }
    public UUID getCustomerId() { return customerId; }
    public UUID getChallengeId() { return challengeId; }
    public CustomerCodeDeliveryProvider.Channel getChannel() { return channel; }
    public CustomerCodeDeliveryProvider.Purpose getPurpose() { return purpose; }
    public String getDestinationDigest() { return destinationDigest; }
    String getProtectedCode() { return protectedCode; }
    public Status getStatus() { return status; }
    public int getAttempts() { return attempts; }
    public int getMaxAttempts() { return maxAttempts; }
    public Instant getNextAttemptAt() { return nextAttemptAt; }
    public Instant getExpiresAt() { return expiresAt; }
    public String getProvider() { return provider; }
    public String getProviderMessageRef() { return providerMessageRef; }
    public String getLastFailure() { return lastFailure; }
    public Instant getSentAt() { return sentAt; }
}
