package com.openwolf.iam.authority.approval;

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

/** Phase 3.7 exact-action approval. Binding facts never change; transitions are one-way. */
@Entity
@Table(name = "action_approvals")
public class ActionApproval {
    public enum Status { PENDING, APPROVED, CONFIRMED, CONSUMED, REJECTED, REVOKED }

    @Id private UUID id;
    @Column(name = "tenant_id", nullable = false) private String tenantId;
    @Column(name = "initiator_principal_id", nullable = false) private String initiator;
    @Column(name = "agent_workload_id", nullable = false) private UUID agentWorkloadId;
    @Column(name = "owner_application_id", nullable = false) private UUID ownerApplicationId;
    @Column(name = "route_id", nullable = false) private UUID routeId;
    @Column(name = "receiver_audience", nullable = false) private String receiverAudience;
    @JdbcTypeCode(SqlTypes.JSON) @Column(nullable = false, columnDefinition = "jsonb") private List<String> scopes;
    @Column(name = "action_type", nullable = false) private String actionType;
    @Column(name = "canonical_action", nullable = false) private String canonicalAction;
    @Column(name = "action_digest", nullable = false) private String actionDigest;
    @JdbcTypeCode(SqlTypes.JSON) @Column(name = "required_acr", nullable = false, columnDefinition = "jsonb")
    private List<String> requiredAcr;
    @Column(name = "max_auth_age_seconds", nullable = false) private int maxAuthAgeSeconds;
    @Column(nullable = false) private Instant deadline;
    @Enumerated(EnumType.STRING) @Column(nullable = false) private Status status;
    @Column(nullable = false) private long version;
    @Column(name = "approver_principal_id") private String approver;
    @Column(name = "approved_at") private Instant approvedAt;
    @Column(name = "approver_auth_time") private Instant approverAuthTime;
    @Column(name = "confirmed_at") private Instant confirmedAt;
    @Column(name = "confirmation_auth_time") private Instant confirmationAuthTime;
    @Column(name = "confirmation_acr") private String confirmationAcr;
    @Column(name = "consumed_at") private Instant consumedAt;
    @Column(name = "consumed_by_client") private String consumedByClient;
    @Column(name = "ended_at") private Instant endedAt;
    @Column(name = "end_reason") private String endReason;
    @Column(name = "created_at", nullable = false) private Instant createdAt;

    protected ActionApproval() {}

    ActionApproval(String tenantId, String initiator, UUID agentWorkloadId, UUID ownerApplicationId, UUID routeId,
                   String receiverAudience, List<String> scopes, String actionType, ActionCanonicalizer.Canonical action,
                   List<String> requiredAcr, int maxAuthAgeSeconds, Instant deadline, Instant now) {
        this.id = UUID.randomUUID();
        this.tenantId = tenantId;
        this.initiator = initiator;
        this.agentWorkloadId = agentWorkloadId;
        this.ownerApplicationId = ownerApplicationId;
        this.routeId = routeId;
        this.receiverAudience = receiverAudience;
        this.scopes = List.copyOf(scopes);
        this.actionType = actionType;
        this.canonicalAction = action.json();
        this.actionDigest = action.digest();
        this.requiredAcr = List.copyOf(requiredAcr);
        this.maxAuthAgeSeconds = maxAuthAgeSeconds;
        this.deadline = deadline;
        this.status = Status.PENDING;
        this.version = 1;
        this.createdAt = now;
    }

    void approve(String approver, Instant authTime, Instant now) {
        if (status != Status.PENDING) throw new IllegalStateException("approval is not pending");
        this.approver = approver;
        this.approverAuthTime = authTime;
        this.approvedAt = now;
        this.status = Status.APPROVED;
        this.version++;
    }

    void confirm(Instant authTime, String acr, Instant now) {
        if (status != Status.APPROVED) throw new IllegalStateException("approval is not awaiting confirmation");
        this.confirmationAuthTime = authTime;
        this.confirmationAcr = acr;
        this.confirmedAt = now;
        this.status = Status.CONFIRMED;
        this.version++;
    }

    boolean end(Status terminal, String reason, Instant now) {
        if (status == Status.REJECTED || status == Status.REVOKED) return false;
        if (terminal == Status.REJECTED && status != Status.PENDING) throw new IllegalStateException("approval is not pending");
        this.status = terminal;
        this.version++;
        this.endedAt = now;
        this.endReason = reason;
        return true;
    }

    public UUID getId() { return id; }
    public String getTenantId() { return tenantId; }
    public String getInitiator() { return initiator; }
    public UUID getAgentWorkloadId() { return agentWorkloadId; }
    public UUID getOwnerApplicationId() { return ownerApplicationId; }
    public UUID getRouteId() { return routeId; }
    public String getReceiverAudience() { return receiverAudience; }
    public List<String> getScopes() { return scopes; }
    public String getActionType() { return actionType; }
    public String getCanonicalAction() { return canonicalAction; }
    public String getActionDigest() { return actionDigest; }
    public List<String> getRequiredAcr() { return requiredAcr; }
    public int getMaxAuthAgeSeconds() { return maxAuthAgeSeconds; }
    public Instant getDeadline() { return deadline; }
    public Status getStatus() { return status; }
    public long getVersion() { return version; }
    public String getApprover() { return approver; }
    public Instant getApprovedAt() { return approvedAt; }
    public Instant getConfirmedAt() { return confirmedAt; }
    public Instant getConfirmationAuthTime() { return confirmationAuthTime; }
    public String getConfirmationAcr() { return confirmationAcr; }
    public Instant getConsumedAt() { return consumedAt; }
    public String getConsumedByClient() { return consumedByClient; }
    public Instant getEndedAt() { return endedAt; }
    public String getEndReason() { return endReason; }
    public Instant getCreatedAt() { return createdAt; }
}
