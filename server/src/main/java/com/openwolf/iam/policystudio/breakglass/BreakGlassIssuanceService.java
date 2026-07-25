package com.openwolf.iam.policystudio.breakglass;

import com.openwolf.iam.policystudio.api.StudioSessionStore;
import com.openwolf.iam.policystudio.lifecycle.PromotionReceipt;
import org.springframework.stereotype.Service;
import org.springframework.scheduling.annotation.Scheduled;

import java.util.List;
import java.util.Set;

/**
 * Durable C6 issuance coordinator. The ledger is written before promotion; ACTIVATED is durable before
 * the GRANTED audit is attempted. Therefore an audit outage leaves an explicit outbox item and a retry
 * never repeats activation (C5 uses the stable grant idempotency key).
 */
@Service
public class BreakGlassIssuanceService {

    private final BreakGlassIssuanceRepository issuances;
    private final BreakGlassApprovalService approvals;
    private final BreakGlassPromotionService promotions;
    private final BreakGlassAuditPartition audit;
    private final BreakGlassBundleGrantRepository bundleGrants;

    public BreakGlassIssuanceService(BreakGlassIssuanceRepository issuances,
                                     BreakGlassApprovalService approvals,
                                     BreakGlassPromotionService promotions,
                                     BreakGlassAuditPartition audit,
                                     BreakGlassBundleGrantRepository bundleGrants) {
        this.issuances = issuances;
        this.approvals = approvals;
        this.promotions = promotions;
        this.audit = audit;
        this.bundleGrants = bundleGrants;
    }

    public BreakGlassIssuance issue(StudioSessionStore.PendingGrant pending, String approver,
                                    Set<String> approverRoles, String correlationId) {
        approvals.authorizeIssue(pending.artifact(), pending.requestedBy(), approver, approverRoles);

        BreakGlassIssuance issuance = issuances.findById(pending.grantId()).orElseGet(() ->
                issuances.saveAndFlush(new BreakGlassIssuance(pending, approver, correlationId)));
        issuance.assertSameIntent(pending, approver);

        if (issuance.getState() == BreakGlassIssuance.State.PENDING) {
            try {
                PromotionReceipt receipt = promotions.mergeAndPromote(
                        pending, approver, approverRoles, issuance.getCorrelationId());
                issuance.markActivated(receipt.fromBundleId(), receipt.toBundleId());
                issuance = issuances.saveAndFlush(issuance);
            } catch (RuntimeException failure) {
                issuance.markError(failure);
                issuances.saveAndFlush(issuance);
                throw failure;
            }
        }

        ensureBundleLineage(issuance);

        return recordActivationAudit(issuance);
    }

    /** Reconcile durable ACTIVATED rows whose audit append previously failed. */
    public int reconcileActivated() {
        List<BreakGlassIssuance> pendingAudit = issuances.findByStateAndAuditRecordedFalse(
                BreakGlassIssuance.State.ACTIVATED);
        int completed = 0;
        for (BreakGlassIssuance issuance : pendingAudit) {
            ensureBundleLineage(issuance);
            recordActivationAudit(issuance);
            completed++;
        }
        return completed;
    }

    @Scheduled(fixedDelayString = "${iam.break-glass.issuance-reconcile-ms:5000}")
    public void scheduledReconcileActivated() {
        reconcileActivated();
    }

    private BreakGlassIssuance recordActivationAudit(BreakGlassIssuance issuance) {
        if (issuance.isAuditRecorded()) {
            return issuance;
        }
        try {
            audit.recordGranted(issuance.grant(), issuance.getApprovedBy(), issuance.getCorrelationId());
            issuance.markAuditRecorded();
            return issuances.saveAndFlush(issuance);
        } catch (RuntimeException failure) {
            issuance.markError(failure);
            issuances.saveAndFlush(issuance);
            throw failure;
        }
    }

    private void ensureBundleLineage(BreakGlassIssuance issuance) {
        String to = issuance.getActiveBundleId();
        if (issuance.getFromBundleId() != null) {
            for (BreakGlassBundleGrant inherited : bundleGrants.findByBundleId(issuance.getFromBundleId())) {
                String id = to + ":" + inherited.getGrantId();
                if (!bundleGrants.existsById(id)) {
                    bundleGrants.save(new BreakGlassBundleGrant(to, inherited.getGrantId()));
                }
            }
        }
        String currentId = to + ":" + issuance.getGrantId();
        if (!bundleGrants.existsById(currentId)) {
            bundleGrants.save(new BreakGlassBundleGrant(to, issuance.getGrantId()));
        }
    }
}
