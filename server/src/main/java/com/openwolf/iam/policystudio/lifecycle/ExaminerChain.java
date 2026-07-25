package com.openwolf.iam.policystudio.lifecycle;

/**
 * A fully reconstructed audit chain for one recorded authorization decision (Axiom Story C5.1/C5.6),
 * joined entirely from IMMUTABLE records with NO LLM:
 *
 * <pre>
 *   application audit (cerbosCallId + activePolicyVersion)
 *     → Cerbos decision entry (same call id, same version)
 *     → immutable bundle record (bundleId = activePolicyVersion)
 *     → Git commit
 *     → approvals + tests
 * </pre>
 *
 * A chain is {@code complete} only if every hop resolved and every cross-check held (version match,
 * bundle integrity, a signature-valid APPROVE, present Git anchor and test metadata). The examiner never
 * returns a partial chain — a broken join is an {@link AuditIntegrityException}, not a half-filled value.
 */
public record ExaminerChain(
        String transactionId,
        String tenantId,
        String cerbosCallId,
        String activePolicyVersion,
        String decision,
        String resourceKind,
        String action,
        String bundleId,
        String gitCommit,
        BundleTestMetadata testMetadata,
        String approverId,
        String consequenceReviewHash,
        boolean approvalSignatureValid,
        boolean complete) {
}
