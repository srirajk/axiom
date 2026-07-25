package com.openwolf.iam.tenancy;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

/** Commits lifecycle-lock reconciliation evidence and the guarded clear as one short transaction. */
@Component
public class LifecycleLockReconciliationLedger {

    private final JdbcTemplate jdbc;
    private final AuditPartitionAdapter audit;

    public LifecycleLockReconciliationLedger(JdbcTemplate jdbc, AuditPartitionAdapter audit) {
        this.jdbc = jdbc;
        this.audit = audit;
    }

    @Transactional
    public boolean clearIfExpired(String tenantId, String expectedOwner,
                                  TenantLifecycleLockStore.ReconciliationEvidence evidence) {
        int deleted = jdbc.update("""
                DELETE FROM tenant_lifecycle_locks
                WHERE tenant_id = ? AND owner_key = ? AND lease_until < now()
        """, tenantId, expectedOwner);
        if (deleted != 1) return false;
        // Approval is evidence that the guarded clear succeeded. Delete first so a no-op cannot
        // leave a durable approval record, and let any audit failure roll the delete back.
        audit.recordLifecycleLockRecoveryEvent(tenantId, evidence.approver(),
                "tenant.lifecycle_lock_recovery_approved", evidence.correlationId(), evidence.payload());
        audit.recordLifecycleLockRecoveryEvent(tenantId, evidence.approver(),
                "tenant.lifecycle_lock_reconciled", evidence.correlationId(), evidence.payload());
        return true;
    }
}
