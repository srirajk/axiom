package com.openwolf.iam.authority.consent;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import jakarta.persistence.Version;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.UUID;

/** Operator-registered purpose under which a customer may delegate to one Agent workload (Phase 3.2). */
@Entity
@Table(name = "agent_workload_purposes")
public class AgentWorkloadPurpose {
    public enum Status { ACTIVE, RETIRED }

    @Id private UUID id;
    @Column(name = "tenant_id", nullable = false) private String tenantId;
    @Column(name = "agent_workload_id", nullable = false) private UUID agentWorkloadId;
    @Column(name = "purpose_code", nullable = false) private String purposeCode;
    @Column(nullable = false) private String description;
    @JdbcTypeCode(SqlTypes.JSON) @Column(name = "allowed_scopes", nullable = false, columnDefinition = "jsonb")
    private List<String> allowedScopes;
    @Column(name = "max_validity_seconds", nullable = false) private long maxValiditySeconds;
    @Enumerated(EnumType.STRING) @Column(nullable = false) private Status status;
    @Column(name = "created_at", nullable = false) private Instant createdAt;
    @Column(name = "retired_at") private Instant retiredAt;
    @Version @Column(nullable = false) private long revision;

    protected AgentWorkloadPurpose() {}

    AgentWorkloadPurpose(String tenantId, UUID agentWorkloadId, String purposeCode, String description,
                         List<String> allowedScopes, Duration maxValidity, Instant now) {
        this.id = UUID.randomUUID();
        this.tenantId = tenantId;
        this.agentWorkloadId = agentWorkloadId;
        this.purposeCode = purposeCode;
        this.description = description;
        this.allowedScopes = List.copyOf(allowedScopes);
        this.maxValiditySeconds = maxValidity.toSeconds();
        this.status = Status.ACTIVE;
        this.createdAt = now;
    }

    void retire(Instant now) {
        if (status == Status.RETIRED) return;
        status = Status.RETIRED;
        retiredAt = now;
    }

    public UUID getId() { return id; }
    public String getTenantId() { return tenantId; }
    public UUID getAgentWorkloadId() { return agentWorkloadId; }
    public String getPurposeCode() { return purposeCode; }
    public String getDescription() { return description; }
    public List<String> getAllowedScopes() { return allowedScopes; }
    public Duration getMaxValidity() { return Duration.ofSeconds(maxValiditySeconds); }
    public Status getStatus() { return status; }
    public Instant getCreatedAt() { return createdAt; }
    public Instant getRetiredAt() { return retiredAt; }
    public long getRevision() { return revision; }
}
