package com.openwolf.iam.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

/**
 * Immutable audit record — every write operation in the IAM service emits one.
 * <p>
 * {@code occurredAt} is set explicitly (NOT via {@code @CreatedDate}) so that
 * the timestamp is always captured at the moment the audited action was performed,
 * not when the entity is persisted.
 * </p>
 */
@Entity
@Table(name = "audit_log")
public class AuditLog {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @Column(name = "tenant_id", nullable = false)
    private String tenantId;

    @Column(name = "actor_id")
    private String actorId;

    @Column(name = "client_id", nullable = false)
    private String clientId = "system";

    @Column(nullable = false)
    private String action;

    @Column(name = "resource_type")
    private String resourceType;

    @Column(name = "resource_id")
    private String resourceId;

    @JdbcTypeCode(SqlTypes.JSON)
    @Column(name = "before_state", columnDefinition = "jsonb")
    private String beforeState;

    @JdbcTypeCode(SqlTypes.JSON)
    @Column(name = "after_state", columnDefinition = "jsonb")
    private String afterState;

    @Column(name = "source_ip")
    private String sourceIp;

    @Column(name = "correlation_id")
    private String correlationId;

    /**
     * Set explicitly — never relying on JPA auditing for audit log timestamps.
     */
    @Column(name = "occurred_at", nullable = false)
    private Instant occurredAt;

    protected AuditLog() {}

    public AuditLog(String tenantId, String actorId, String clientId, String action,
                    String resourceType, String resourceId,
                    String beforeState, String afterState,
                    String sourceIp, String correlationId) {
        this.tenantId = tenantId;
        this.actorId = actorId;
        this.clientId = clientId != null ? clientId : "system";
        this.action = action;
        this.resourceType = resourceType;
        this.resourceId = resourceId;
        this.beforeState = beforeState;
        this.afterState = afterState;
        this.sourceIp = sourceIp;
        this.correlationId = correlationId;
        this.occurredAt = Instant.now();
    }

    public UUID getId() { return id; }
    public String getTenantId() { return tenantId; }
    public String getActorId() { return actorId; }
    public String getClientId() { return clientId; }
    public String getAction() { return action; }
    public String getResourceType() { return resourceType; }
    public String getResourceId() { return resourceId; }
    public String getBeforeState() { return beforeState; }
    public String getAfterState() { return afterState; }
    public String getSourceIp() { return sourceIp; }
    public String getCorrelationId() { return correlationId; }
    public Instant getOccurredAt() { return occurredAt; }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof AuditLog)) return false;
        AuditLog auditLog = (AuditLog) o;
        return Objects.equals(id, auditLog.id);
    }

    @Override
    public int hashCode() {
        return Objects.hash(id);
    }
}
