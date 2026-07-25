package com.openwolf.iam.policystudio;

import java.time.Instant;
import java.util.List;
import java.util.Set;

/**
 * A signed approval bound to the exact machine consequences a human approved (Axiom Story C4.6). It
 * signs the {@code consequenceReviewHash} — which itself binds the tenant, both bundle ids, the sampled
 * fixture matrix, and the canonical machine delta — so the approval cryptographically commits to the
 * precise decision changes the approver saw, not to a policy paraphrase and not to display wording.
 *
 * <p>Promotion accepts ONLY the exact (currentBundleId, candidateBundleId, consequenceReviewHash)
 * tuple carried here (see {@link ConsequenceApprovalService#authorizesPromotion}). Any change to a
 * truth input yields a different review hash and this record no longer authorizes it; changing only the
 * review's display prose does not change the hash, so the approval still stands.
 *
 * @param tenantId              the tenant the approval is for
 * @param currentBundleId       the current bundle the approved diff was computed against
 * @param candidateBundleId     the candidate bundle the approval authorizes
 * @param fixtureSetHash        the sampled matrix the approved diff covered
 * @param consequenceReviewHash the exact review hash the approver signed
 * @param overPermissionAlarm   whether the approved diff carried the over-permission alarm (audit)
 * @param approverId            the approving principal
 * @param approverRoles         the approver's roles at decision time
 * @param decision              APPROVE or REJECT
 * @param signature             HMAC-SHA256 over the approval payload (tamper-evidence)
 * @param signedAt              when the approval was signed
 */
public record ConsequenceApprovalRecord(
        String tenantId,
        String currentBundleId,
        String candidateBundleId,
        String fixtureSetHash,
        String consequenceReviewHash,
        boolean overPermissionAlarm,
        String approverId,
        Set<String> approverRoles,
        ApprovalDecision decision,
        String signature,
        Instant signedAt) {

    public ConsequenceApprovalRecord {
        approverRoles = Set.copyOf(approverRoles);
    }

    /**
     * The exact bytes the signature covers. Order-stable and includes every binding field: the review
     * hash (which already binds the truth), plus the approver identity, decision and timestamp so the
     * signature also attests WHO approved WHAT and WHEN.
     */
    public String signingPayload() {
        return "consequence-approval-v1"
                + "\ntenant=" + tenantId
                + "\ncurrent=" + currentBundleId
                + "\ncandidate=" + candidateBundleId
                + "\nfixtureSet=" + fixtureSetHash
                + "\nreviewHash=" + consequenceReviewHash
                + "\nalarm=" + overPermissionAlarm
                + "\napprover=" + approverId
                + "\nroles=" + List.copyOf(new java.util.TreeSet<>(approverRoles))
                + "\ndecision=" + decision
                + "\nsignedAt=" + signedAt;
    }
}
