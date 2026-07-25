package com.openwolf.iam.policystudio.lifecycle;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

import java.time.Instant;

/**
 * The durable Cerbos decision-log entry for one authorization call (Axiom Story C5), keyed by the
 * {@code cerbosCallId} the application audit index references. It records the decision and — crucially —
 * the {@code activePolicyVersion} (immutable bundle id) the PDP evaluated under. The examiner asserts
 * this version EQUALS the application audit's version; a mismatch means a request was split across bundle
 * versions and is an audit-integrity FAILURE (C5.1/C5.5). Immutable/append-only.
 *
 * <p>{@code ddl-auto: validate} — columns MUST match {@code V11__policy_lifecycle.sql}.
 */
@Entity
@Table(name = "cerbos_decision_log")
public class CerbosDecisionEntry {

    @Id
    @Column(name = "cerbos_call_id")
    private String cerbosCallId;

    @Column(name = "tenant_id", nullable = false)
    private String tenantId;

    @Column(name = "active_policy_version", nullable = false)
    private String activePolicyVersion;

    @Column(name = "decision", nullable = false)
    private String decision;

    @Column(name = "resource_kind")
    private String resourceKind;

    @Column(name = "action")
    private String action;

    @Column(name = "occurred_at", nullable = false)
    private Instant occurredAt;

    protected CerbosDecisionEntry() {}

    public CerbosDecisionEntry(String cerbosCallId, String tenantId, String activePolicyVersion,
                               String decision, String resourceKind, String action, Instant occurredAt) {
        this.cerbosCallId = cerbosCallId;
        this.tenantId = tenantId;
        this.activePolicyVersion = activePolicyVersion;
        this.decision = decision;
        this.resourceKind = resourceKind;
        this.action = action;
        this.occurredAt = occurredAt;
    }

    public String getCerbosCallId() { return cerbosCallId; }
    public String getTenantId() { return tenantId; }
    public String getActivePolicyVersion() { return activePolicyVersion; }
    public String getDecision() { return decision; }
    public String getResourceKind() { return resourceKind; }
    public String getAction() { return action; }
    public Instant getOccurredAt() { return occurredAt; }
}
