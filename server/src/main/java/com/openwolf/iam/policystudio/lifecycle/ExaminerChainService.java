package com.openwolf.iam.policystudio.lifecycle;

import com.openwolf.iam.policystudio.ApprovalDecision;
import com.openwolf.iam.policystudio.ConsequenceApprovalRecord;
import com.openwolf.iam.policystudio.ConsequenceReviewSigner;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.util.List;

/**
 * Reconstructs the full audit chain for a recorded authorization decision from IMMUTABLE records, with
 * ZERO LLM (Axiom Story C5.1/C5.6). It has no model client of any kind — every hop is a deterministic
 * join over durable, content-addressed records:
 *
 * <ol>
 *   <li>the application audit index (by {@code cerbosCallId}) → its {@code activePolicyVersion};</li>
 *   <li>the Cerbos decision log (same call id) → assert its version EQUALS the audit's version (no split
 *       request);</li>
 *   <li>the immutable bundle record (id = the active policy version) → verify content-addressed
 *       integrity, recover the Git commit;</li>
 *   <li>the signed approval (by candidate bundle id) → an APPROVE whose HMAC re-verifies;</li>
 *   <li>the certifying test metadata carried by the bundle.</li>
 * </ol>
 *
 * A missing call id, a mismatched version, an absent bundle/Git/approval/test record, a tampered bundle,
 * or an invalid signature is an {@link AuditIntegrityException} — a FAILURE, never a warning. Because the
 * reconstruction touches only these records and an HMAC verifier (no model), it answers with the LLM
 * subsystem entirely disabled.
 *
 * <p>Authoring-plane only: structurally unreachable from enforcement (see {@code PolicyAuthoringBoundaryArchTest}).
 */
@Service
public class ExaminerChainService {

    private static final Logger log = LoggerFactory.getLogger(ExaminerChainService.class);

    private final ApplicationAuditRepository auditRepo;
    private final CerbosDecisionRepository decisionRepo;
    private final PolicyBundleRepository bundleRepo;
    private final ApprovalRepository approvalRepo;
    private final BundleCanonicalizer canonicalizer;
    private final ConsequenceReviewSigner signer;

    public ExaminerChainService(ApplicationAuditRepository auditRepo,
                                CerbosDecisionRepository decisionRepo,
                                PolicyBundleRepository bundleRepo,
                                ApprovalRepository approvalRepo,
                                BundleCanonicalizer canonicalizer,
                                ConsequenceReviewSigner signer) {
        this.auditRepo = auditRepo;
        this.decisionRepo = decisionRepo;
        this.bundleRepo = bundleRepo;
        this.approvalRepo = approvalRepo;
        this.canonicalizer = canonicalizer;
        this.signer = signer;
    }

    /**
     * Reconstruct the complete chain for a recorded decision (by its Cerbos call id).
     *
     * @throws AuditIntegrityException if any hop is missing or any cross-check fails
     */
    public ExaminerChain reconstruct(String cerbosCallId) {
        // (1) application audit entry — the entry point.
        List<ApplicationAuditEntry> audits = auditRepo.findByCerbosCallId(cerbosCallId);
        if (audits.isEmpty()) {
            throw new AuditIntegrityException(
                    "no application audit entry for cerbosCallId '" + cerbosCallId + "' — the decision cannot "
                            + "be attributed to a request (audit-integrity failure)");
        }
        ApplicationAuditEntry audit = audits.get(0);
        String tenantId = audit.getTenantId();
        if (tenantId == null || tenantId.isBlank()) {
            throw new AuditIntegrityException("application audit entry for cerbosCallId '" + cerbosCallId
                    + "' has no tenant — the examiner chain cannot be tenant-scoped");
        }
        String activeVersion = audit.getActivePolicyVersion();

        // (2) Cerbos decision entry — same call id, and its version MUST match the audit's.
        CerbosDecisionEntry decision = decisionRepo.findById(cerbosCallId).orElseThrow(() ->
                new AuditIntegrityException("no Cerbos decision-log entry for cerbosCallId '" + cerbosCallId
                        + "' — application audit references a decision that is not in the decision log"));
        if (!tenantId.equals(decision.getTenantId())) {
            throw new AuditIntegrityException("tenant mismatch for cerbosCallId '" + cerbosCallId
                    + "': application audit belongs to '" + tenantId + "' but decision log belongs to '"
                    + decision.getTenantId() + "'");
        }
        if (!decision.getActivePolicyVersion().equals(activeVersion)) {
            throw new AuditIntegrityException("policy-version mismatch for cerbosCallId '" + cerbosCallId
                    + "': application audit ran under '" + activeVersion + "' but the decision log recorded '"
                    + decision.getActivePolicyVersion() + "' — a request was split across bundle versions");
        }

        // (3) immutable bundle record — id = the active policy version; verify content-addressed integrity.
        PolicyBundleRecord bundle = bundleRepo.findById(activeVersion).orElseThrow(() ->
                new AuditIntegrityException("no immutable bundle record for active policy version '"
                        + activeVersion + "' — the decision references a bundle that was never recorded"));
        if (!tenantId.equals(bundle.getTenantId())) {
            throw new AuditIntegrityException("tenant mismatch for bundle '" + activeVersion
                    + "': decision chain belongs to '" + tenantId + "' but bundle belongs to '"
                    + bundle.getTenantId() + "'");
        }
        if (!bundle.contentMatchesId(canonicalizer)) {
            throw new AuditIntegrityException("bundle '" + activeVersion + "' fails content-addressed integrity "
                    + "— its stored bytes do not hash to its id (tamper)");
        }

        // (4) Git commit — the immutable record MUST anchor the bundle to a commit.
        String gitCommit = bundle.getGitCommit();
        if (gitCommit == null || gitCommit.isBlank()) {
            throw new AuditIntegrityException("bundle '" + activeVersion + "' has no Git anchor — the "
                    + "immutable record → Git commit join is broken");
        }

        // (5) approvals + tests — a signature-valid APPROVE authorizing this exact bundle.
        List<ApprovalRecordEntity> approvals = approvalRepo.findByCandidateBundleId(activeVersion);
        ApprovalRecordEntity approved = null;
        for (ApprovalRecordEntity a : approvals) {
            ConsequenceApprovalRecord rec = a.toRecord();
            boolean sigValid = rec.decision() == ApprovalDecision.APPROVE
                    && tenantId.equals(rec.tenantId())
                    && signer.verify(rec.signingPayload(), rec.signature());
            if (sigValid) {
                approved = a;
                break;
            }
        }
        if (approved == null) {
            throw new AuditIntegrityException("no signature-valid APPROVE authorizes bundle '" + activeVersion
                    + "' — the bundle → approvals join is broken (active bundle without a complete approval)");
        }

        BundleTestMetadata tests = bundle.testMetadata();
        // testMetadata is non-null by construction; fixtureSetHash is validated in its constructor.

        ExaminerChain chain = new ExaminerChain(
                audit.getTransactionId(), tenantId, cerbosCallId, activeVersion,
                decision.getDecision(), decision.getResourceKind(), decision.getAction(),
                bundle.getBundleId(), gitCommit, tests,
                approved.getApproverId(), approved.getConsequenceReviewHash(), true, true);
        log.debug("Examiner chain reconstructed for call {} (bundle {}, git {}, approver {}) — no LLM",
                cerbosCallId, activeVersion, gitCommit, approved.getApproverId());
        return chain;
    }
}
