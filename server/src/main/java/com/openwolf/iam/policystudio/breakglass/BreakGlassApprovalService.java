package com.openwolf.iam.policystudio.breakglass;

import org.springframework.stereotype.Service;

import java.util.Set;

/**
 * The two-person gate for issuing a break-glass grant (Axiom Story C6.4). It preserves the SAME
 * separation-of-duties invariant C1 enforces on ordinary policy approval via the
 * {@code policy_approval} Cerbos meta-authz (author≠approver; a superuser is not an auto-approver) —
 * emergency access is expedited, never single-person.
 *
 * <p>On approval the issuance is recorded to the tenant's A6 audit partition
 * ({@link BreakGlassAuditPartition#recordGranted}); each subsequent USE of the grant is recorded via
 * {@link #recordUse}. The grant itself is inert until compiled/promoted — this service authorizes
 * the issuance; the PDP alone enforces the time bound.
 */
@Service
public class BreakGlassApprovalService {

    /** One product role shared by the HTTP gate, UI, and service-level SoD enforcement. */
    public static final String APPROVER_ROLE = "policy_approver";

    private final BreakGlassAuditPartition audit;

    public BreakGlassApprovalService(BreakGlassAuditPartition audit) {
        this.audit = audit;
    }

    /**
     * Authorize issuance of a break-glass grant. Fails closed on an inadmissible artifact or an SoD
     * violation. This method does not audit GRANTED; the caller records that only after promotion.
     *
     * <p><b>Separation of duties over VERIFIED identity (H1).</b> The author is the {@code authorId}
     * captured from the authenticated {@code sub} at author time and passed by the caller context —
     * NOT {@code grant.requestedBy()} (a mutable field on the caller-supplied grant record). A missing
     * ({@code null}/blank) author or approver identity <b>fails closed</b> — it is never allowed to
     * skip the self-approval check.
     *
     * @param artifact     the doubly-gated artifact awaiting issuance
     * @param authorId     the VERIFIED identity that authored the grant (captured at author time)
     * @param approverId   the VERIFIED identity approving the grant now
     * @throws IllegalStateException   if the artifact is not admissible (bounds or C2 gate rejected it)
     * @throws BreakGlassSodException  if either identity is missing, the approver is the author, or the
     *                                 approver lacks the approver role
     */
    public void authorizeIssue(BreakGlassArtifact artifact, String authorId, String approverId,
                               Set<String> approverRoles) {
        if (!artifact.admissible()) {
            throw new IllegalStateException(
                    "refusing to approve an inadmissible break-glass artifact — bounds="
                            + artifact.boundsResult().violations() + " c2=" + artifact.c2Result().violations());
        }

        // C6.4 / C1.2 — FAIL CLOSED on a missing verified identity: neither side may be absent, or the
        // author≠approver check could be silently skipped.
        if (authorId == null || authorId.isBlank()) {
            throw new BreakGlassSodException(
                    "separation of duties: the authenticated author identity is required — refusing to "
                            + "approve a break-glass grant with no verified author (fail-closed)");
        }
        if (approverId == null || approverId.isBlank()) {
            throw new BreakGlassSodException(
                    "separation of duties: the authenticated approver identity is required — refusing to "
                            + "approve a break-glass grant with no verified approver (fail-closed)");
        }

        // C6.4 / C1.2 — author≠approver over VERIFIED identity: the author may never approve their own
        // emergency access.
        if (approverId.equals(authorId)) {
            throw new BreakGlassSodException(
                    "separation of duties: '" + approverId + "' authored this break-glass grant and "
                            + "may not also approve it (author≠approver)");
        }
        // C6.4 / C1.3 — approval flows only through a studio approver, never an auto-approving superuser.
        if (approverRoles == null || !approverRoles.contains(APPROVER_ROLE)) {
            throw new BreakGlassSodException(
                    "approver '" + approverId + "' must hold the studio approver role '" + APPROVER_ROLE
                            + "' to approve a break-glass grant (roles=" + approverRoles + ")");
        }
    }

    /**
     * Persist the issuance audit only after promotion has succeeded. Keeping this separate from
     * {@link #authorizeIssue} prevents a failed runtime promotion from leaving a false GRANTED event.
     */
    public void recordIssued(BreakGlassArtifact artifact, String approverId, String correlationId) {
        audit.recordGranted(artifact.grant(), approverId, correlationId);
    }

    /**
     * Convenience operation for non-promoting callers and focused gate tests. Production HTTP issuance
     * deliberately calls {@link #authorizeIssue}, promotes, and only then calls {@link #recordIssued}.
     */
    public void approveAndIssue(BreakGlassArtifact artifact, String authorId, String approverId,
                                Set<String> approverRoles, String correlationId) {
        authorizeIssue(artifact, authorId, approverId, approverRoles);
        recordIssued(artifact, approverId, correlationId);
    }

    /** Record a single use of an issued, still-valid break-glass grant (C6.3). */
    public void recordUse(BreakGlassGrant grant, String principalId, String action, String correlationId) {
        audit.recordUsed(grant, principalId, action, correlationId);
    }
}
