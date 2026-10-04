package com.openwolf.iam.policystudio.breakglass;

import com.openwolf.iam.policystudio.lifecycle.PromotionRecord;
import com.openwolf.iam.policystudio.lifecycle.PromotionRepository;
import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;

import java.time.Instant;
import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

/** Durable recovery of a PENDING break-glass issuance whose C5 promotion committed before ACTIVATED was saved. */
class BreakGlassPendingRecoveryTest {

    private final BreakGlassIssuanceRepository repo = mock(BreakGlassIssuanceRepository.class);
    private final BreakGlassApprovalService approvals = mock(BreakGlassApprovalService.class);
    private final BreakGlassPromotionService promotions = mock(BreakGlassPromotionService.class);
    private final BreakGlassAuditPartition audit = mock(BreakGlassAuditPartition.class);
    private final BreakGlassBundleGrantRepository lineage = mock(BreakGlassBundleGrantRepository.class);
    private final PromotionRepository ledger = mock(PromotionRepository.class);
    private final BreakGlassIssuanceService service =
            new BreakGlassIssuanceService(repo, approvals, promotions, audit, lineage, ledger);

    @Test
    void promotedPendingRowIsActivatedAndAuditedOnceWithoutPromotingAgain() {
        BreakGlassIssuance row = issuance("bg-1", "bob");
        rows(row);
        when(ledger.findByIdempotencyKey("break-glass:bg-1"))
                .thenReturn(Optional.of(promoted("bg-1", "acme", "bob", PromotionRecord.Kind.PROMOTION)));

        int completed = service.reconcileActivated();

        assertThat(completed).isEqualTo(1);
        assertThat(row.getState()).isEqualTo(BreakGlassIssuance.State.ACTIVATED);
        assertThat(row.getFromBundleId()).isEqualTo("b_base");
        assertThat(row.getActiveBundleId()).isEqualTo("b_active");
        assertThat(row.isAuditRecorded()).isTrue();
        verify(audit, times(1)).recordGranted(any(), eq("bob"), eq("corr-bg-1"));
        verify(lineage).save(any(BreakGlassBundleGrant.class));
        verifyNoInteractions(promotions, approvals);
    }

    @Test
    void missingFailedOrRollbackRecordsLeaveTheRowPendingUntouched() {
        BreakGlassIssuance missing = issuance("bg-missing", "bob");
        BreakGlassIssuance failed = issuance("bg-failed", "bob");
        BreakGlassIssuance rollback = issuance("bg-rollback", "bob");
        rows(missing, failed, rollback);
        when(ledger.findByIdempotencyKey("break-glass:bg-missing")).thenReturn(Optional.empty());
        PromotionRecord failedRecord = new PromotionRecord("break-glass:bg-failed", "acme", "b_base", "b_active",
                "crh", "bob", PromotionRecord.Kind.PROMOTION);   // FAILED: also the in-flight initial state
        when(ledger.findByIdempotencyKey("break-glass:bg-failed")).thenReturn(Optional.of(failedRecord));
        when(ledger.findByIdempotencyKey("break-glass:bg-rollback"))
                .thenReturn(Optional.of(promoted("bg-rollback", "acme", "bob", PromotionRecord.Kind.ROLLBACK)));

        assertThat(service.reconcileActivated()).isZero();

        for (BreakGlassIssuance row : List.of(missing, failed, rollback)) {
            assertThat(row.getState()).isEqualTo(BreakGlassIssuance.State.PENDING);
            assertThat(row.getLastError()).isNull();
        }
        verify(repo, never()).saveAndFlush(any());
        verifyNoInteractions(audit, promotions);
    }

    @Test
    void promotedRecordForADifferentIntentIsRecordedAsAnErrorAndStaysPending() {
        BreakGlassIssuance row = issuance("bg-2", "bob");
        rows(row);
        when(ledger.findByIdempotencyKey("break-glass:bg-2"))
                .thenReturn(Optional.of(promoted("bg-2", "acme", "mallory", PromotionRecord.Kind.PROMOTION)));

        service.reconcileActivated();

        assertThat(row.getState()).isEqualTo(BreakGlassIssuance.State.PENDING);
        assertThat(row.getLastError()).contains("does not match");
        verifyNoInteractions(audit, promotions);
    }

    @Test
    void oneFailingRowDoesNotPreventRecoveryOfOthers() {
        BreakGlassIssuance first = issuance("bg-a", "bob");
        BreakGlassIssuance second = issuance("bg-b", "bob");
        rows(first, second);
        when(ledger.findByIdempotencyKey("break-glass:bg-a"))
                .thenThrow(new IllegalStateException("ledger read failed"));
        when(ledger.findByIdempotencyKey("break-glass:bg-b"))
                .thenReturn(Optional.of(promoted("bg-b", "acme", "bob", PromotionRecord.Kind.PROMOTION)));

        assertThat(service.reconcileActivated()).isEqualTo(1);

        assertThat(first.getState()).isEqualTo(BreakGlassIssuance.State.PENDING);
        assertThat(first.getLastError()).contains("ledger read failed");
        assertThat(second.isAuditRecorded()).isTrue();
    }

    @Test
    void auditFailureOnOneActivatedRowDoesNotStopTheNext() {
        BreakGlassIssuance first = issuance("bg-c", "bob");
        BreakGlassIssuance second = issuance("bg-d", "bob");
        first.markActivated("b_base", "b_c");
        second.markActivated("b_base", "b_d");
        rows(first, second);
        doThrow(new IllegalStateException("audit unavailable"))
                .when(audit).recordGranted(any(), eq("bob"), eq("corr-bg-c"));

        assertThat(service.reconcileActivated()).isEqualTo(1);

        assertThat(first.isAuditRecorded()).isFalse();
        assertThat(first.getLastError()).contains("audit unavailable");
        assertThat(second.isAuditRecorded()).isTrue();
    }

    @Test
    void compatibilityConstructorWithoutLedgerNeverRecoversPendingRows() {
        BreakGlassIssuanceService legacy = new BreakGlassIssuanceService(repo, approvals, promotions, audit, lineage);
        BreakGlassIssuance row = issuance("bg-e", "bob");
        rows(row);

        assertThat(legacy.reconcileActivated()).isZero();
        assertThat(row.getState()).isEqualTo(BreakGlassIssuance.State.PENDING);
        verifyNoInteractions(ledger, audit);
    }

    // -----------------------------------------------------------------------------------------------------------------

    /** The repository returns rows by their live state, like the database would on each query. */
    private void rows(BreakGlassIssuance... all) {
        when(repo.findByStateAndAuditRecordedFalse(any())).thenAnswer(call -> {
            BreakGlassIssuance.State state = call.getArgument(0);
            return java.util.Arrays.stream(all).filter(r -> r.getState() == state && !r.isAuditRecorded()).toList();
        });
        when(repo.saveAndFlush(any())).thenAnswer(call -> call.getArgument(0));
    }

    private static BreakGlassIssuance issuance(String grantId, String approver) {
        BreakGlassIssuance row = org.springframework.beans.BeanUtils.instantiateClass(BreakGlassIssuance.class);
        Instant now = Instant.now();
        ReflectionTestUtils.setField(row, "grantId", grantId);
        ReflectionTestUtils.setField(row, "tenantId", "acme");
        ReflectionTestUtils.setField(row, "scope", "acme");
        ReflectionTestUtils.setField(row, "resourceKind", "iam-resource");
        ReflectionTestUtils.setField(row, "action", "read");
        ReflectionTestUtils.setField(row, "role", "tenant_admin");
        ReflectionTestUtils.setField(row, "issuedAt", now);
        ReflectionTestUtils.setField(row, "expiresAt", now.plusSeconds(1800));
        ReflectionTestUtils.setField(row, "requestedBy", "alice");
        ReflectionTestUtils.setField(row, "approvedBy", approver);
        ReflectionTestUtils.setField(row, "correlationId", "corr-" + grantId);
        ReflectionTestUtils.setField(row, "state", BreakGlassIssuance.State.PENDING);
        ReflectionTestUtils.setField(row, "createdAt", now);
        ReflectionTestUtils.setField(row, "updatedAt", now);
        return row;
    }

    private static PromotionRecord promoted(String grantId, String tenant, String approver, PromotionRecord.Kind kind) {
        PromotionRecord record = new PromotionRecord("break-glass:" + grantId, tenant, "b_base", "b_active", "crh",
                approver, kind);
        record.markPromoted(2L);
        return record;
    }
}
