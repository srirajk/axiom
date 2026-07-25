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
@Table(name = "identity_control_requests")
public class IdentityControlRequest {
    public enum Action {
        EMERGENCY_RETIRE_SIGNING_KEY,
        DISABLE_IDENTITY_SOURCE,
        ROTATE_IDENTITY_SOURCE_SECRET,
        REVOKE_APPLICATION_CLIENT_SECRET,
        ROTATE_APPLICATION_CLIENT_SECRET,
        REVOKE_SCIM_SOURCE,
        ROTATE_SCIM_SOURCE_CREDENTIAL
    }

    public enum TargetType { SIGNING_KEY, IDENTITY_SOURCE, APPLICATION_CLIENT, SCIM_SOURCE }
    public enum Status { PENDING, APPROVED, APPLIED, REJECTED, EXPIRED, CANCELLED }

    @Id private UUID id;
    @Column(name = "tenant_id", nullable = false) private String tenantId;
    @Enumerated(EnumType.STRING) @Column(nullable = false) private Action action;
    @Enumerated(EnumType.STRING) @Column(name = "target_type", nullable = false) private TargetType targetType;
    @Column(name = "target_id", nullable = false) private UUID targetId;
    @Column(name = "payload_hash", nullable = false, length = 64) private String payloadHash;
    @Column(name = "payload_ciphertext") private String payloadCiphertext;
    @Column(name = "initiator_principal_id", nullable = false) private String initiatorPrincipalId;
    @Column(name = "created_at", nullable = false) private Instant createdAt;
    @Column(name = "expires_at", nullable = false) private Instant expiresAt;
    @Column(name = "expected_target_revision") private Long expectedTargetRevision;
    @Enumerated(EnumType.STRING) @Column(nullable = false) private Status status;
    @Column(name = "approver_principal_id") private String approverPrincipalId;
    @Column(name = "approved_at") private Instant approvedAt;
    @Column(name = "application_result_reference") private String applicationResultReference;
    @Version @Column(nullable = false) private long revision;

    protected IdentityControlRequest() {}

    public IdentityControlRequest(String tenantId, Action action, TargetType targetType, UUID targetId,
                                  String payloadHash, String payloadCiphertext, String initiatorPrincipalId,
                                  Instant createdAt, Instant expiresAt, Long expectedTargetRevision) {
        this.id = UUID.randomUUID(); this.tenantId = tenantId; this.action = action; this.targetType = targetType;
        this.targetId = targetId; this.payloadHash = payloadHash; this.payloadCiphertext = payloadCiphertext;
        this.initiatorPrincipalId = initiatorPrincipalId; this.createdAt = createdAt; this.expiresAt = expiresAt;
        this.expectedTargetRevision = expectedTargetRevision; this.status = Status.PENDING; this.revision = 1;
    }

    public void approve(String approver, Instant at) {
        status = Status.APPROVED; approverPrincipalId = approver; approvedAt = at;
    }
    public void reject() { status = Status.REJECTED; }
    public void cancel() { status = Status.CANCELLED; }
    public void expire() { status = Status.EXPIRED; }
    public void apply(String resultReference) { status = Status.APPLIED; applicationResultReference = resultReference; }

    public UUID getId() { return id; }
    public String getTenantId() { return tenantId; }
    public Action getAction() { return action; }
    public TargetType getTargetType() { return targetType; }
    public UUID getTargetId() { return targetId; }
    public String getPayloadHash() { return payloadHash; }
    public String getPayloadCiphertext() { return payloadCiphertext; }
    public String getInitiatorPrincipalId() { return initiatorPrincipalId; }
    public Instant getCreatedAt() { return createdAt; }
    public Instant getExpiresAt() { return expiresAt; }
    public Long getExpectedTargetRevision() { return expectedTargetRevision; }
    public Status getStatus() { return status; }
    public String getApproverPrincipalId() { return approverPrincipalId; }
    public Instant getApprovedAt() { return approvedAt; }
    public String getApplicationResultReference() { return applicationResultReference; }
    public long getRevision() { return revision; }
}
