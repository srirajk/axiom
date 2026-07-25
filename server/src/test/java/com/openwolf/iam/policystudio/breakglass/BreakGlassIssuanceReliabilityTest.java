package com.openwolf.iam.policystudio.breakglass;

import com.openwolf.iam.policystudio.GeneratedPolicyValidator;
import com.openwolf.iam.policystudio.PolicyIR;
import com.openwolf.iam.policystudio.api.StudioSessionStore;
import com.openwolf.iam.policystudio.lifecycle.PromotionReceipt;
import com.openwolf.iam.policystudio.lifecycle.PromotionRecord;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

class BreakGlassIssuanceReliabilityTest {

    @Test
    void auditFailureLeavesActivatedOutboxAndRetryDoesNotPromoteTwice() {
        BreakGlassIssuanceRepository repo = mock(BreakGlassIssuanceRepository.class);
        BreakGlassApprovalService approvals = mock(BreakGlassApprovalService.class);
        BreakGlassPromotionService promotions = mock(BreakGlassPromotionService.class);
        BreakGlassAuditPartition audit = mock(BreakGlassAuditPartition.class);
        BreakGlassBundleGrantRepository lineage = mock(BreakGlassBundleGrantRepository.class);
        StudioSessionStore.PendingGrant pending = pending();
        AtomicReference<BreakGlassIssuance> stored = new AtomicReference<>();
        when(repo.findById("bg-1")).thenAnswer(ignored -> Optional.ofNullable(stored.get()));
        when(repo.saveAndFlush(any())).thenAnswer(invocation -> {
            BreakGlassIssuance value = invocation.getArgument(0);
            stored.set(value);
            return value;
        });
        when(promotions.mergeAndPromote(any(), eq("bob"), any(), eq("corr-1")))
                .thenReturn(new PromotionReceipt("p-1", "acme", "base", "b_active", 2,
                        PromotionRecord.Kind.PROMOTION, false));
        doThrow(new IllegalStateException("audit unavailable")).doNothing()
                .when(audit).recordGranted(any(), eq("bob"), eq("corr-1"));
        BreakGlassIssuanceService service =
                new BreakGlassIssuanceService(repo, approvals, promotions, audit, lineage);

        assertThatThrownBy(() -> service.issue(pending, "bob", Set.of("policy_approver"), "corr-1"))
                .hasMessageContaining("audit unavailable");
        assertThat(stored.get().getState()).isEqualTo(BreakGlassIssuance.State.ACTIVATED);
        assertThat(stored.get().isAuditRecorded()).isFalse();
        assertThat(stored.get().getActiveBundleId()).isEqualTo("b_active");

        BreakGlassIssuance reconciled =
                service.issue(pending, "bob", Set.of("policy_approver"), "different-retry-correlation");

        assertThat(reconciled.isAuditRecorded()).isTrue();
        verify(promotions, times(1)).mergeAndPromote(any(), any(), any(), any());
        verify(audit, times(2)).recordGranted(any(), eq("bob"), eq("corr-1"));
    }

    @Test
    void scheduledReconcileRepairsLineageBeforeRecordingActivationAudit() {
        BreakGlassIssuanceRepository repo = mock(BreakGlassIssuanceRepository.class);
        BreakGlassApprovalService approvals = mock(BreakGlassApprovalService.class);
        BreakGlassPromotionService promotions = mock(BreakGlassPromotionService.class);
        BreakGlassAuditPartition audit = mock(BreakGlassAuditPartition.class);
        BreakGlassBundleGrantRepository lineage = mock(BreakGlassBundleGrantRepository.class);
        AtomicReference<BreakGlassIssuance> stored = new AtomicReference<>();
        when(repo.findById("bg-1")).thenReturn(Optional.empty());
        when(repo.saveAndFlush(any())).thenAnswer(call -> {
            BreakGlassIssuance value = call.getArgument(0); stored.set(value); return value;
        });
        when(promotions.mergeAndPromote(any(), any(), any(), any()))
                .thenReturn(new PromotionReceipt("p", "acme", "base", "b_active", 2,
                        PromotionRecord.Kind.PROMOTION, false));
        when(lineage.save(any())).thenThrow(new IllegalStateException("lineage unavailable"))
                .thenAnswer(call -> call.getArgument(0));
        BreakGlassIssuanceService service =
                new BreakGlassIssuanceService(repo, approvals, promotions, audit, lineage);

        assertThatThrownBy(() -> service.issue(pending(), "bob", Set.of("policy_approver"), "corr"))
                .hasMessageContaining("lineage unavailable");
        assertThat(stored.get().getState()).isEqualTo(BreakGlassIssuance.State.ACTIVATED);
        verifyNoInteractions(audit);

        when(repo.findByStateAndAuditRecordedFalse(BreakGlassIssuance.State.ACTIVATED))
                .thenReturn(List.of(stored.get()));
        assertThat(service.reconcileActivated()).isEqualTo(1);
        assertThat(stored.get().isAuditRecorded()).isTrue();
        verify(audit).recordGranted(any(), eq("bob"), eq("corr"));
    }

    @Test
    void durableAllowDecisionIsProjectedToIdempotentUseWithGrantIdentity() {
        BreakGlassDecisionEventRepository decisions = mock(BreakGlassDecisionEventRepository.class);
        BreakGlassIssuanceRepository issuances = mock(BreakGlassIssuanceRepository.class);
        BreakGlassAuditPartition audit = mock(BreakGlassAuditPartition.class);
        BreakGlassBundleGrantRepository lineage = mock(BreakGlassBundleGrantRepository.class);
        BreakGlassIssuance issuance = new BreakGlassIssuance(pending(), "bob", "corr-1");
        issuance.markActivated("base", "b_B"); // grant1 was first activated in B
        Instant usedAt = pending().artifact().grant().issuedAt().plusSeconds(10);
        BreakGlassDecisionEvent decision = new BreakGlassDecisionEvent(
                "call-123", "acme", "b_C", "ALLOW", "principal-7", "agent",
                "agent-42", "register", Set.of("platform_admin"), usedAt);
        when(decisions.findByDecisionAndProcessedFalseOrderByOccurredAt("ALLOW")).thenReturn(List.of(decision));
        // A later sequential grant produced C and copied grant1's rule; immutable lineage retains that edge.
        when(lineage.findByBundleId("b_C")).thenReturn(List.of(new BreakGlassBundleGrant("b_C", "bg-1")));
        when(issuances.findAllById(List.of("bg-1"))).thenReturn(List.of(issuance));

        int count = new BreakGlassUseAuditReconciler(decisions, issuances, audit, lineage).reconcile();

        assertThat(count).isEqualTo(1);
        verify(audit).recordUsed(eq("bg-1"), any(), eq("principal-7"), eq("register"), eq("call-123"));
    }

    @Test
    void allowForPrincipalWithoutGrantedRoleIsNotRecordedAsBreakGlassUse() {
        BreakGlassDecisionEventRepository decisions = mock(BreakGlassDecisionEventRepository.class);
        BreakGlassIssuanceRepository issuances = mock(BreakGlassIssuanceRepository.class);
        BreakGlassAuditPartition audit = mock(BreakGlassAuditPartition.class);
        BreakGlassBundleGrantRepository lineage = mock(BreakGlassBundleGrantRepository.class);
        BreakGlassIssuance issuance = new BreakGlassIssuance(pending(), "bob", "corr-1");
        issuance.markActivated("base", "b_active");
        BreakGlassDecisionEvent decision = new BreakGlassDecisionEvent(
                "call-other", "acme", "b_active", "ALLOW", "ordinary-user", "agent",
                "agent-42", "register", Set.of("chat_user"), issuance.getIssuedAt().plusSeconds(10));
        when(decisions.findByDecisionAndProcessedFalseOrderByOccurredAt("ALLOW")).thenReturn(List.of(decision));
        when(lineage.findByBundleId("b_active")).thenReturn(List.of(new BreakGlassBundleGrant("b_active", "bg-1")));
        when(issuances.findAllById(List.of("bg-1"))).thenReturn(List.of(issuance));

        assertThat(new BreakGlassUseAuditReconciler(decisions, issuances, audit, lineage).reconcile()).isZero();
        assertThat(decision.isProcessed()).isFalse();
        verifyNoInteractions(audit);
    }

    @Test
    void overlappingSameTupleUseIsAttributedOnlyToNewestGrant() {
        BreakGlassDecisionEventRepository decisions = mock(BreakGlassDecisionEventRepository.class);
        BreakGlassIssuanceRepository issuances = mock(BreakGlassIssuanceRepository.class);
        BreakGlassAuditPartition audit = mock(BreakGlassAuditPartition.class);
        BreakGlassBundleGrantRepository lineage = mock(BreakGlassBundleGrantRepository.class);
        BreakGlassIssuance older = new BreakGlassIssuance(
                pending("bg-1", Instant.parse("2026-07-17T10:00:00Z")), "bob", "c1");
        BreakGlassIssuance newer = new BreakGlassIssuance(
                pending("bg-2", Instant.parse("2026-07-17T10:05:00Z")), "carol", "c2");
        older.markActivated("base", "b_B");
        newer.markActivated("b_B", "b_C");
        BreakGlassDecisionEvent decision = new BreakGlassDecisionEvent(
                "call-overlap", "acme", "b_C", "ALLOW", "principal-7", "agent", "agent-42",
                "register", Set.of("platform_admin"), Instant.parse("2026-07-17T10:10:00Z"));
        when(decisions.findByDecisionAndProcessedFalseOrderByOccurredAt("ALLOW")).thenReturn(List.of(decision));
        when(lineage.findByBundleId("b_C")).thenReturn(List.of(
                new BreakGlassBundleGrant("b_C", "bg-1"), new BreakGlassBundleGrant("b_C", "bg-2")));
        when(issuances.findAllById(List.of("bg-1", "bg-2"))).thenReturn(List.of(older, newer));

        assertThat(new BreakGlassUseAuditReconciler(decisions, issuances, audit, lineage).reconcile()).isEqualTo(1);
        verify(audit).recordUsed(eq("bg-2"), any(), eq("principal-7"), eq("register"), eq("call-overlap"));
        verify(audit, never()).recordUsed(eq("bg-1"), any(), any(), any(), any());
    }

    private static StudioSessionStore.PendingGrant pending() {
        return pending("bg-1", Instant.parse("2026-07-17T10:00:00Z"));
    }

    private static StudioSessionStore.PendingGrant pending(String grantId, Instant issued) {
        BreakGlassGrant grant = new BreakGlassGrant(
                com.openwolf.iam.policystudio.TenantScope.of("acme"), "agent", "register", "platform_admin",
                issued, issued.plusSeconds(1800), "incident", "alice");
        PolicyIR ir = new PolicyIR("api.cerbos.dev/v1", "default", "agent", "acme",
                "SCOPE_PERMISSIONS_REQUIRE_PARENTAL_CONSENT_FOR_ALLOWS", List.of(), List.of());
        BreakGlassArtifact artifact = new BreakGlassArtifact(grant, ir, "",
                new BreakGlassValidator.Result(true, List.of()),
                new GeneratedPolicyValidator.Result(true, List.of()));
        return new StudioSessionStore.PendingGrant(grantId, "acme", "alice", artifact, false, issued);
    }
}
