package com.openwolf.iam.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import org.hibernate.annotations.Immutable;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

import java.time.Instant;
import java.util.UUID;

@Entity
@Immutable
@Table(name = "ciam_lifecycle_events")
public class CiamLifecycleEvent {
    @Id private UUID id;
    @Column(name = "tenant_id", nullable = false) private String tenantId;
    @Column(name = "actor_id") private String actorId;
    @Column(name = "event_type", nullable = false) private String eventType;
    @Column(name = "subject_type", nullable = false) private String subjectType;
    @Column(name = "subject_id", nullable = false) private String subjectId;
    @JdbcTypeCode(SqlTypes.JSON) @Column(nullable = false, columnDefinition = "jsonb") private String details;
    @Column(name = "correlation_id") private String correlationId;
    @Column(name = "occurred_at", nullable = false) private Instant occurredAt;

    protected CiamLifecycleEvent() {}

    public CiamLifecycleEvent(String tenantId, String actorId, String eventType,
                              String subjectType, String subjectId, String details,
                              String correlationId, Instant occurredAt) {
        this.id = UUID.randomUUID();
        this.tenantId = tenantId;
        this.actorId = actorId;
        this.eventType = eventType;
        this.subjectType = subjectType;
        this.subjectId = subjectId;
        this.details = details;
        this.correlationId = correlationId;
        this.occurredAt = occurredAt;
    }

    public UUID getId() { return id; }
    public String getTenantId() { return tenantId; }
    public String getActorId() { return actorId; }
    public String getEventType() { return eventType; }
    public String getSubjectType() { return subjectType; }
    public String getSubjectId() { return subjectId; }
    public String getDetails() { return details; }
    public String getCorrelationId() { return correlationId; }
    public Instant getOccurredAt() { return occurredAt; }
}
