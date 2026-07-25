package com.openwolf.iam.policystudio.breakglass;

import com.openwolf.iam.policystudio.TenantScope;
import com.openwolf.iam.policystudio.api.StudioSessionStore;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

import java.time.Instant;

/** Durable C6 issuance/outbox row: PENDING promotion → ACTIVATED, then audit_recorded. */
@Entity
@Table(name = "break_glass_issuances")
public class BreakGlassIssuance {

    public enum State { PENDING, ACTIVATED }

    @Id @Column(name = "grant_id") private String grantId;
    @Column(name = "tenant_id", nullable = false) private String tenantId;
    @Column(nullable = false) private String scope;
    @Column(name = "resource_kind", nullable = false) private String resourceKind;
    @Column(nullable = false) private String action;
    @Column(name = "role_name", nullable = false) private String role;
    @Column(name = "issued_at", nullable = false) private Instant issuedAt;
    @Column(name = "expires_at", nullable = false) private Instant expiresAt;
    @Column(name = "requested_by", nullable = false) private String requestedBy;
    @Column private String justification;
    @Column(name = "approved_by", nullable = false) private String approvedBy;
    @Column(name = "correlation_id", nullable = false) private String correlationId;
    @Enumerated(EnumType.STRING) @Column(nullable = false) private State state;
    @Column(name = "from_bundle_id") private String fromBundleId;
    @Column(name = "active_bundle_id") private String activeBundleId;
    @Column(name = "audit_recorded", nullable = false) private boolean auditRecorded;
    @Column(name = "last_error") private String lastError;
    @Column(name = "created_at", nullable = false) private Instant createdAt;
    @Column(name = "updated_at", nullable = false) private Instant updatedAt;

    protected BreakGlassIssuance() {}

    public BreakGlassIssuance(StudioSessionStore.PendingGrant pending, String approvedBy, String correlationId) {
        BreakGlassGrant grant = pending.artifact().grant();
        this.grantId = pending.grantId();
        this.tenantId = pending.tenantId();
        this.scope = grant.scope().value();
        this.resourceKind = grant.resourceKind();
        this.action = grant.action();
        this.role = grant.role();
        this.issuedAt = grant.issuedAt();
        this.expiresAt = grant.expiresAt();
        this.requestedBy = pending.requestedBy();
        this.justification = grant.justification();
        this.approvedBy = approvedBy;
        this.correlationId = correlationId;
        this.state = State.PENDING;
        this.createdAt = Instant.now();
        this.updatedAt = createdAt;
    }

    public void assertSameIntent(StudioSessionStore.PendingGrant pending, String approver) {
        BreakGlassGrant grant = pending.artifact().grant();
        if (!tenantId.equals(pending.tenantId()) || !scope.equals(grant.scope().value())
                || !resourceKind.equals(grant.resourceKind()) || !action.equals(grant.action())
                || !role.equals(grant.role()) || !requestedBy.equals(pending.requestedBy())
                || !approvedBy.equals(approver)) {
            throw new IllegalStateException("break-glass grant id was reused with a different issuance intent");
        }
    }

    public void markActivated(String fromBundleId, String bundleId) {
        state = State.ACTIVATED;
        this.fromBundleId = fromBundleId;
        activeBundleId = bundleId;
        lastError = null;
        updatedAt = Instant.now();
    }

    public void markAuditRecorded() {
        auditRecorded = true;
        lastError = null;
        updatedAt = Instant.now();
    }

    public void markError(RuntimeException error) {
        lastError = error.toString();
        updatedAt = Instant.now();
    }

    public BreakGlassGrant grant() {
        return new BreakGlassGrant(TenantScope.of(scope), resourceKind, action, role, issuedAt, expiresAt,
                justification, requestedBy);
    }

    public String getGrantId() { return grantId; }
    public String getTenantId() { return tenantId; }
    public State getState() { return state; }
    public String getActiveBundleId() { return activeBundleId; }
    public String getFromBundleId() { return fromBundleId; }
    public boolean isAuditRecorded() { return auditRecorded; }
    public String getApprovedBy() { return approvedBy; }
    public String getCorrelationId() { return correlationId; }
    public String getLastError() { return lastError; }
    public String getResourceKind() { return resourceKind; }
    public String getAction() { return action; }
    public String getRole() { return role; }
    public Instant getIssuedAt() { return issuedAt; }
    public Instant getExpiresAt() { return expiresAt; }
}
