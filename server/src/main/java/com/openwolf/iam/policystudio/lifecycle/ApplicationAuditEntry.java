package com.openwolf.iam.policystudio.lifecycle;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

import java.time.Instant;
import java.util.UUID;

/**
 * The examiner's entry point: the application-side audit index for one Cerbos decision on the request
 * path (Axiom Story C5). It mirrors the serving audit record's promoted join keys — the
 * {@code cerbosCallId} captured on the request and the {@code activePolicyVersion} (the immutable bundle
 * id) the request ran under (A2/A6) — so the examiner can start from a recorded decision and walk to the
 * durable Cerbos decision log, the bundle, the Git commit, and the approvals/tests. Immutable/append-only.
 *
 * <p>{@code ddl-auto: validate} — columns MUST match {@code V11__policy_lifecycle.sql}.
 */
@Entity
@Table(name = "application_audit_index")
public class ApplicationAuditEntry {

    @Id
    @Column(name = "id")
    private UUID id;

    @Column(name = "transaction_id", nullable = false)
    private String transactionId;

    @Column(name = "tenant_id", nullable = false)
    private String tenantId;

    @Column(name = "cerbos_call_id", nullable = false)
    private String cerbosCallId;

    @Column(name = "active_policy_version", nullable = false)
    private String activePolicyVersion;

    @Column(name = "occurred_at", nullable = false)
    private Instant occurredAt;

    protected ApplicationAuditEntry() {}

    public ApplicationAuditEntry(String transactionId, String tenantId, String cerbosCallId,
                                 String activePolicyVersion, Instant occurredAt) {
        this.id = UUID.randomUUID();
        this.transactionId = transactionId;
        this.tenantId = tenantId;
        this.cerbosCallId = cerbosCallId;
        this.activePolicyVersion = activePolicyVersion;
        this.occurredAt = occurredAt;
    }

    public String getId() { return id.toString(); }
    public String getTransactionId() { return transactionId; }
    public String getTenantId() { return tenantId; }
    public String getCerbosCallId() { return cerbosCallId; }
    public String getActivePolicyVersion() { return activePolicyVersion; }
    public Instant getOccurredAt() { return occurredAt; }
}
