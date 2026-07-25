package com.openwolf.iam.policystudio.breakglass;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

import java.time.Instant;
import java.util.Arrays;
import java.util.Set;
import java.util.TreeSet;

/** One resource/action output from a potentially batched Cerbos decision-log line. */
@Entity
@Table(name = "break_glass_decision_events")
public class BreakGlassDecisionEvent {
    @Id @Column(name = "event_id") private String eventId;
    @Column(name = "cerbos_call_id", nullable = false) private String cerbosCallId;
    @Column(name = "tenant_id", nullable = false) private String tenantId;
    @Column(name = "active_policy_version", nullable = false) private String activePolicyVersion;
    @Column(nullable = false) private String decision;
    @Column(name = "principal_id", nullable = false) private String principalId;
    @Column(name = "principal_roles", nullable = false) private String principalRoles;
    @Column(name = "resource_kind", nullable = false) private String resourceKind;
    @Column(name = "resource_id", nullable = false) private String resourceId;
    @Column(nullable = false) private String action;
    @Column(name = "occurred_at", nullable = false) private Instant occurredAt;
    @Column(nullable = false) private boolean processed;

    protected BreakGlassDecisionEvent() {}

    public BreakGlassDecisionEvent(String callId, String tenantId, String version, String decision,
                                   String principalId, String resourceKind, String resourceId,
                                   String action, Set<String> principalRoles, Instant occurredAt) {
        this.eventId = callId + ":" + resourceId + ":" + action;
        this.cerbosCallId = callId;
        this.tenantId = tenantId;
        this.activePolicyVersion = version;
        this.decision = decision;
        this.principalId = principalId;
        this.principalRoles = String.join(",", new TreeSet<>(principalRoles));
        this.resourceKind = resourceKind;
        this.resourceId = resourceId;
        this.action = action;
        this.occurredAt = occurredAt;
    }

    public void markProcessed() { processed = true; }
    public String getEventId() { return eventId; }
    public String getCerbosCallId() { return cerbosCallId; }
    public String getTenantId() { return tenantId; }
    public String getActivePolicyVersion() { return activePolicyVersion; }
    public String getDecision() { return decision; }
    public String getPrincipalId() { return principalId; }
    public Set<String> getPrincipalRoles() {
        return principalRoles == null || principalRoles.isBlank() ? Set.of()
                : Set.copyOf(Arrays.asList(principalRoles.split(",")));
    }
    public String getResourceKind() { return resourceKind; }
    public String getResourceId() { return resourceId; }
    public String getAction() { return action; }
    public Instant getOccurredAt() { return occurredAt; }
    public boolean isProcessed() { return processed; }
}
