package com.openwolf.iam.policystudio.lifecycle;

import com.openwolf.iam.policystudio.ConsequenceApprovalRecord;
import com.openwolf.iam.tenancy.ActiveTenantDirectory;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

/**
 * Short database boundaries for policy promotion. No method in the promotion orchestrator keeps a
 * transaction open across parsing, Cerbos/PDP probes, or runtime-policy publication.
 */
@Component
public class PromotionLedger {

    private final ActiveTenantDirectory directory;
    private final PromotionRepository promotions;
    private final PolicyBundleRepository bundles;
    private final ApprovalRepository approvals;

    public PromotionLedger(ActiveTenantDirectory directory,
                           PromotionRepository promotions,
                           PolicyBundleRepository bundles,
                           ApprovalRepository approvals) {
        this.directory = directory;
        this.promotions = promotions;
        this.bundles = bundles;
        this.approvals = approvals;
    }

    /** Create the durable intent row and commit it before any external promotion work starts. */
    @Transactional
    public PromotionRecord startOrResume(PromotionRequest request) {
        promotions.lockIdempotencyKey(request.idempotencyKey());
        return promotions.findByIdempotencyKey(request.idempotencyKey()).orElseGet(() ->
                promotions.save(new PromotionRecord(
                        request.idempotencyKey(), request.tenantId(), request.reviewedCurrentBundleId(),
                        request.candidate().bundleId(), request.review().consequenceReviewHash(),
                        request.approval().approverId(), request.kind())));
    }

    /**
     * Commit the last-mile state transition only after runtime publication has succeeded. The active
     * directory CAS, immutable bundle record, signed approval and PROMOTED receipt are one short DB
     * boundary; no Cerbos, filesystem, S3 or network call occurs here.
     */
    @Transactional
    public long compareAndPromote(PromotionRequest request, PromotionRecord operation, String gitCommit) {
        PromotionRecord persisted = promotions.findByIdempotencyKeyForUpdate(request.idempotencyKey())
                .orElseThrow(() -> new PromotionExecutionBusyException("promotion ledger row disappeared"));
        if (persisted.getStatus() == PromotionRecord.Status.PROMOTED) {
            return persisted.getDirectoryVersion() == null ? 0L : persisted.getDirectoryVersion();
        }
        long directoryVersion;
        try {
            directoryVersion = directory.compareAndActivate(
                    request.tenantId(), request.reviewedCurrentBundleId(), request.candidate().bundleId());
        } catch (IllegalStateException stale) {
            throw new StalePromotionException(stale.getMessage());
        }
        if (!bundles.existsById(request.candidate().bundleId())) {
            bundles.save(new PolicyBundleRecord(request.candidate(), gitCommit));
        }
        approvals.save(new ApprovalRecordEntity(request.approval()));
        persisted.markPromoted(directoryVersion);
        promotions.save(persisted);
        return directoryVersion;
    }

    /** Persist a retryable failure after all external work has stopped. */
    @Transactional
    public void markFailed(PromotionRecord operation, RuntimeException failure) {
        promotions.markFailedIfNotPromoted(operation.getIdempotencyKey(), failure.toString(),
                PromotionRecord.Status.FAILED, PromotionRecord.Status.PROMOTED);
    }
}
