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
import java.util.UUID;

@Entity
@Table(name = "customer_delegation_grants")
public class CustomerDelegationGrant {
    public enum Status { ACTIVE, REVOKED, EXPIRED }

    @Id private UUID id;
    @Column(name = "tenant_id", nullable = false) private String tenantId;
    @Column(name = "customer_id", nullable = false) private UUID customerId;
    @Column(name = "agent_workload_id", nullable = false) private UUID agentWorkloadId;
    @Column(nullable = false) private String audience;
    @JdbcTypeCode(SqlTypes.JSON) @Column(nullable = false, columnDefinition = "jsonb") private String scopes;
    @Column(nullable = false) private String purpose;
    @Enumerated(EnumType.STRING) @Column(nullable = false) private Status status;
    @Column(name = "consent_recorded_at", nullable = false) private Instant consentRecordedAt;
    @Column(name = "expires_at", nullable = false) private Instant expiresAt;
    @Column(name = "revoked_at") private Instant revokedAt;
    @Column(name = "revocation_reason") private String revocationReason;
    @Column(name = "created_at", nullable = false) private Instant createdAt;
    @Version @Column(nullable = false) private long revision;
    @Column(name = "purpose_code") private String purposeCode;
    @Column(name = "consent_source") private String consentSource;

    protected CustomerDelegationGrant() {}

    public CustomerDelegationGrant(String tenantId, UUID customerId, UUID agentWorkloadId,
                                   String audience, String scopes, String purpose,
                                   Instant expiresAt, Instant now) {
        this.id = UUID.randomUUID();
        this.tenantId = tenantId;
        this.customerId = customerId;
        this.agentWorkloadId = agentWorkloadId;
        this.audience = audience;
        this.scopes = scopes;
        this.purpose = purpose;
        this.status = Status.ACTIVE;
        this.consentRecordedAt = now;
        this.expiresAt = expiresAt;
        this.createdAt = now;
    }

    /** Phase 3.2: binds the grant to a registered purpose; only consent recorded by the customer may carry one. */
    public CustomerDelegationGrant consent(String purposeCode, boolean recordedByCustomer) {
        if (purposeCode != null && !recordedByCustomer) {
            throw new IllegalStateException("purpose-bound consent must be recorded by the customer");
        }
        this.purposeCode = purposeCode;
        this.consentSource = recordedByCustomer ? "CUSTOMER" : "ADMINISTRATOR";
        return this;
    }

    public void revoke(String reason, Instant now) {
        if (status == Status.REVOKED) return;
        status = Status.REVOKED;
        revokedAt = now;
        revocationReason = reason;
    }

    public boolean isUsableAt(Instant now) {
        return status == Status.ACTIVE && expiresAt.isAfter(now);
    }

    public UUID getId() { return id; }
    public String getTenantId() { return tenantId; }
    public UUID getCustomerId() { return customerId; }
    public UUID getAgentWorkloadId() { return agentWorkloadId; }
    public String getAudience() { return audience; }
    public String getScopes() { return scopes; }
    public String getPurpose() { return purpose; }
    public Status getStatus() { return status; }
    public Instant getConsentRecordedAt() { return consentRecordedAt; }
    public Instant getExpiresAt() { return expiresAt; }
    public Instant getRevokedAt() { return revokedAt; }
    public String getRevocationReason() { return revocationReason; }
    public Instant getCreatedAt() { return createdAt; }
    public long getRevision() { return revision; }
    public String getPurposeCode() { return purposeCode; }
    public String getConsentSource() { return consentSource; }
}
