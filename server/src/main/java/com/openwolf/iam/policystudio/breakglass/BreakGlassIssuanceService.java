package com.openwolf.iam.policystudio.breakglass;

import com.openwolf.iam.policystudio.api.StudioSessionStore;
import com.openwolf.iam.policystudio.lifecycle.PromotionReceipt;
import com.openwolf.iam.policystudio.lifecycle.PromotionRecord;
import com.openwolf.iam.policystudio.lifecycle.PromotionRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.scheduling.annotation.Scheduled;

import java.util.List;
import java.util.Optional;
import java.util.Set;

/**
 * Durable C6 issuance coordinator. The ledger is written before promotion; ACTIVATED is durable before
 * the GRANTED audit is attempted. Therefore an audit outage leaves an explicit outbox item and a retry
 * never repeats activation (C5 uses the stable grant idempotency key).
 */
@Service
public class BreakGlassIssuanceService {

    private static final Logger log = LoggerFactory.getLogger(BreakGlassIssuanceService.class);

    private final BreakGlassIssuanceRepository issuances;
    private final BreakGlassApprovalService approvals;
    private final BreakGlassPromotionService promotions;
    private final BreakGlassAuditPartition audit;
    private final BreakGlassBundleGrantRepository bundleGrants;
    /** Durable C5 ledger. Null disables PENDING recovery (rows then stay PENDING: fail-closed). */
    private final PromotionRepository promotionLedger;

    /** Compatibility constructor without the promotion ledger: PENDING rows are never recovered. */
    public BreakGlassIssuanceService(BreakGlassIssuanceRepository issuances,
                                     BreakGlassApprovalService approvals,
                                     BreakGlassPromotionService promotions,
                                     BreakGlassAuditPartition audit,
                                     BreakGlassBundleGrantRepository bundleGrants) {
        this(issuances, approvals, promotions, audit, bundleGrants, null);
    }

    @Autowired
    public BreakGlassIssuanceService(BreakGlassIssuanceRepository issuances,
                                     BreakGlassApprovalService approvals,
                                     BreakGlassPromotionService promotions,
                                     BreakGlassAuditPartition audit,
                                     BreakGlassBundleGrantRepository bundleGrants,
                                     PromotionRepository promotionLedger) {
        this.issuances = issuances;
        this.approvals = approvals;
        this.promotions = promotions;
        this.audit = audit;
        this.bundleGrants = bundleGrants;
        this.promotionLedger = promotionLedger;
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

    /**
     * Reconcile durable issuance rows using durable state only (no in-memory pending grant is needed, so this works
     * after a restart):
     * <ol>
     *   <li>PENDING rows whose C5 promotion is recorded PROMOTED (crash after promotion, before ACTIVATED was saved)
     *       are marked ACTIVATED with the recorded bundle ids. Nothing is ever promoted here.</li>
     *   <li>ACTIVATED rows without a GRANTED audit get their bundle lineage and the (idempotent) audit.</li>
     * </ol>
     * Every row is isolated: a failure is recorded on that row and the remaining rows are still processed.
     *
     * @return the number of ACTIVATED rows whose audit was completed in this pass
     */
    public int reconcileActivated() {
        for (BreakGlassIssuance pending : issuances.findByStateAndAuditRecordedFalse(BreakGlassIssuance.State.PENDING)) {
            try {
                recoverPromotedPending(pending);
            } catch (RuntimeException failure) {
                recordRowFailure(pending, failure);
            }
        }
        int completed = 0;
        for (BreakGlassIssuance issuance : issuances.findByStateAndAuditRecordedFalse(
                BreakGlassIssuance.State.ACTIVATED)) {
            try {
                ensureBundleLineage(issuance);
                recordActivationAudit(issuance);
                completed++;
            } catch (RuntimeException failure) {
                recordRowFailure(issuance, failure);
            }
        }
        return completed;
    }

    /**
     * Mark a PENDING row ACTIVATED only when the durable C5 ledger proves its promotion committed for the same intent.
     * A missing record, a FAILED record (also the initial state of an in-flight promotion) or a ROLLBACK leaves the
     * row PENDING untouched; a PROMOTED record that does not match the row's tenant or approver is recorded as an
     * error and the row stays PENDING.
     */
    private void recoverPromotedPending(BreakGlassIssuance pending) {
        if (promotionLedger == null) return;
        Optional<PromotionRecord> recorded = promotionLedger.findByIdempotencyKey(
                BreakGlassPromotionService.idempotencyKey(pending.getGrantId()));
        if (recorded.isEmpty()) return;
        PromotionRecord promotion = recorded.get();
        if (promotion.getStatus() != PromotionRecord.Status.PROMOTED
                || promotion.getKind() != PromotionRecord.Kind.PROMOTION) {
            return;
        }
        if (!pending.getTenantId().equals(promotion.getTenantId())
                || !pending.getApprovedBy().equals(promotion.getApproverId())
                || promotion.getToBundleId() == null || promotion.getToBundleId().isBlank()) {
            throw new IllegalStateException("break-glass promotion record does not match the issuance intent");
        }
        pending.markActivated(promotion.getFromBundleId(), promotion.getToBundleId());
        issuances.saveAndFlush(pending);
        log.warn("Break-glass grant '{}' recovered from PENDING using durable promotion '{}' (tenant '{}'): {} → {}",
                pending.getGrantId(), promotion.getId(), pending.getTenantId(), promotion.getFromBundleId(),
                promotion.getToBundleId());
    }

    private void recordRowFailure(BreakGlassIssuance issuance, RuntimeException failure) {
        log.error("Break-glass issuance reconciliation failed for grant '{}' (state {}): {}",
                issuance.getGrantId(), issuance.getState(), failure.toString());
        try {
            issuance.markError(failure);
            issuances.saveAndFlush(issuance);
        } catch (RuntimeException ignored) {
            // The row keeps its previous durable state and is retried on the next pass.
        }
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
