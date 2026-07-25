package com.openwolf.iam.tenancy;

import org.junit.jupiter.api.Test;
import org.mockito.InOrder;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.transaction.annotation.Transactional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.*;

/** Locks the guarded-delete plus approval/reconciled-audit transaction boundary. */
class LifecycleLockReconciliationLedgerTest {

    @Test
    void auditFailureIsInsideTheTransactionalClearBoundary() throws Exception {
        JdbcTemplate jdbc = mock(JdbcTemplate.class);
        AuditPartitionAdapter audit = mock(AuditPartitionAdapter.class);
        LifecycleLockReconciliationLedger ledger = new LifecycleLockReconciliationLedger(jdbc, audit);
        when(jdbc.update(anyString(), eq("tenant-a"), eq("owner-a"))).thenReturn(1);
        doThrow(new IllegalStateException("audit unavailable")).when(audit)
                .recordLifecycleLockRecoveryEvent(anyString(), anyString(),
                        eq("tenant.lifecycle_lock_reconciled"), anyString(), anyString());
        TenantLifecycleLockStore.ReconciliationEvidence evidence = evidence();

        assertThatThrownBy(() -> ledger.clearIfExpired("tenant-a", "owner-a", evidence))
                .isInstanceOf(IllegalStateException.class);
        assertThat(LifecycleLockReconciliationLedger.class
                .getMethod("clearIfExpired", String.class, String.class,
                        TenantLifecycleLockStore.ReconciliationEvidence.class)
                .isAnnotationPresent(Transactional.class)).isTrue();
        InOrder order = inOrder(jdbc, audit);
        order.verify(jdbc).update(anyString(), eq("tenant-a"), eq("owner-a"));
        order.verify(audit).recordLifecycleLockRecoveryEvent("tenant-a", "approver-b",
                "tenant.lifecycle_lock_recovery_approved", "corr-a", "approval-payload");
        order.verify(audit).recordLifecycleLockRecoveryEvent("tenant-a", "approver-b",
                "tenant.lifecycle_lock_reconciled", "corr-a", "approval-payload");
    }

    @Test
    void failedGuardDoesNotWriteAnApprovalRecord() {
        JdbcTemplate jdbc = mock(JdbcTemplate.class);
        AuditPartitionAdapter audit = mock(AuditPartitionAdapter.class);
        LifecycleLockReconciliationLedger ledger = new LifecycleLockReconciliationLedger(jdbc, audit);
        when(jdbc.update(anyString(), any(), any())).thenReturn(0);

        assertThat(ledger.clearIfExpired("tenant-a", "wrong-owner", evidence())).isFalse();
        verifyNoInteractions(audit);
    }

    private static TenantLifecycleLockStore.ReconciliationEvidence evidence() {
        return new TenantLifecycleLockStore.ReconciliationEvidence(
                "operator-a", "approver-b", "corr-a", "evidence-hash", "approval-payload",
                true, true, true, true);
    }
}
