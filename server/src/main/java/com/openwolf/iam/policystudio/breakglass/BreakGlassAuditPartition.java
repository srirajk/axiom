package com.openwolf.iam.policystudio.breakglass;

import com.openwolf.iam.entity.AuditLog;

import java.util.List;

/**
 * The break-glass audit sink (Axiom Story C6.3), writing into the tenant's A6 audit partition — the
 * {@code tenant_id}-scoped slice of {@code audit_log} that outlives the tenant for the evidence
 * obligation. BOTH the ISSUANCE of a grant and EVERY USE of it are recorded, so an emergency access
 * event is fully reconstructable after the fact. Append-only; there is no delete.
 */
public interface BreakGlassAuditPartition {

    /** Record that a break-glass grant was issued (two-person approved) into the tenant partition. */
    void recordGranted(BreakGlassGrant grant, String approverId, String correlationId);

    /** Record a single USE of an active break-glass grant (a principal exercised the emergency access). */
    void recordUsed(BreakGlassGrant grant, String principalId, String action, String correlationId);

    /** Same event with the durable grant identity included in evidence. */
    default void recordUsed(String grantId, BreakGlassGrant grant, String principalId,
                            String action, String correlationId) {
        recordUsed(grant, principalId, action, correlationId);
    }

    /** The tenant's audit partition slice (A6), newest first. */
    List<AuditLog> partition(String tenantId);
}
