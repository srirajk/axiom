package com.openwolf.iam.policystudio;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Optional;
import java.util.Set;

/**
 * Binds a human approval to the exact machine consequences of a {@link ConsequenceReview} (Axiom Story
 * C4.6) and enforces the no-stale-diff rule (C4.5).
 *
 * <p>{@link #approve} refuses to sign a review that is stale (the tenant's active bundle drifted from
 * the diff's captured current bundle) or tampered (its hash no longer matches its truth fields). A
 * produced {@link ConsequenceApprovalRecord} signs the {@code consequenceReviewHash}, so
 * {@link #authorizesPromotion} accepts only the exact current/candidate/review-hash tuple the human
 * saw. Changing any truth input (candidate, current, fixture set, one delta cell) changes the review
 * hash and invalidates the approval; changing only display wording does not.
 */
@Service
public class ConsequenceApprovalService {

    /** Default approver roles when none is configured — the roles legitimately empowered to sign a
     *  consequence approval. {@code platform_admin} is deliberately absent (it is a super-admin, never an
     *  auto-approver of a policy change). Configurable via {@code iam.policy-studio.approver-roles}. */
    private static final Set<String> DEFAULT_APPROVER_ROLES =
            Set.of("policy_approver", "security_reviewer", "domain_owner");

    private final ConsequenceReviewSigner signer;
    private final TenantActiveBundleRegistry activeBundles;
    private final ReviewAuthorRegistry authors;
    private final Set<String> approverRoles;

    /**
     * Production wiring. The approver-role set is config-driven (World B: config, not code);
     * {@code platform_admin} is not in the default set, so it can never be an auto-approver.
     */
    @Autowired
    public ConsequenceApprovalService(
            ConsequenceReviewSigner signer,
            TenantActiveBundleRegistry activeBundles,
            ReviewAuthorRegistry authors,
            @Value("${iam.policy-studio.approver-roles:policy_approver,security_reviewer,domain_owner}")
            Set<String> approverRoles) {
        this.signer = signer;
        this.activeBundles = activeBundles;
        this.authors = authors;
        this.approverRoles = approverRoles == null || approverRoles.isEmpty()
                ? DEFAULT_APPROVER_ROLES : Set.copyOf(approverRoles);
    }

    /**
     * Convenience constructor (no author registry) — the C4 hash-binding / staleness contract with no
     * separation-of-duties source. author≠approver is inert (no recorded author to match); the approver
     * role gate uses the default approver-role set.
     */
    public ConsequenceApprovalService(ConsequenceReviewSigner signer, TenantActiveBundleRegistry activeBundles) {
        this(signer, activeBundles, (tenantId, reviewHash) -> Optional.empty(), DEFAULT_APPROVER_ROLES);
    }

    /**
     * Sign an approval for a review — the API entry point (approver identity is the VERIFIED principal;
     * the approver's tenant is the review's tenant, already asserted at the controller). Delegates to the
     * enforced {@link #approve(ConsequenceReview, ApproverIdentity, ApprovalDecision)}.
     *
     * @throws StaleReviewException if the tenant's active bundle no longer equals the review's captured
     *                              current bundle (C4.5) — a fresh diff is required first
     * @throws IllegalStateException if the review's hash does not match its truth fields (tamper), the
     *                               approver lacks an approver role, the approver is the review's author,
     *                               or the approver identity is null (fail closed)
     */
    public ConsequenceApprovalRecord approve(
            ConsequenceReview review, String approverId, Set<String> approverRoles, ApprovalDecision decision) {
        return approve(review, new ApproverIdentity(review.tenantId(), approverId, approverRoles), decision);
    }

    /**
     * Sign an approval for a review, enforcing the Axiom H3 approver gate from VERIFIED identity before
     * the C4 staleness/tamper checks:
     * <ul>
     *   <li><b>null approver → fail closed</b> (never a skipped check);</li>
     *   <li><b>approver role required</b> — the approver must hold a configured approver role;
     *       {@code platform_admin} alone is rejected (no auto-approval);</li>
     *   <li><b>tenant match</b> — the approver must be in the review's tenant;</li>
     *   <li><b>author≠approver</b> — from the author recorded server-side at review-compute time
     *       ({@link ReviewAuthorRegistry}), never a caller-supplied id.</li>
     * </ul>
     */
    public ConsequenceApprovalRecord approve(
            ConsequenceReview review, ApproverIdentity approver, ApprovalDecision decision) {

        // (H3) VERIFIED approver identity — a null/blank subject FAILS CLOSED, never skips the gate.
        if (approver == null || approver.subject() == null || approver.subject().isBlank()) {
            throw new IllegalStateException(
                    "approver identity is null/blank — refusing to sign an approval (fail closed)");
        }
        String approverId = approver.subject();

        // (H3) approver role — must hold a configured approver role; platform_admin alone is excluded.
        if (Collections.disjoint(approver.roles(), approverRoles)) {
            throw new IllegalStateException(
                    "approver '" + approverId + "' holds none of the approver roles " + sorted(approverRoles)
                            + " (roles were " + sorted(approver.roles())
                            + ") — a policy approval requires an approver role; platform_admin is not an "
                            + "auto-approver");
        }

        // (H3) tenant match — the approver must be in the review's tenant (defence in depth for the API).
        if (!review.tenantId().equals(approver.tenantId())) {
            throw new IllegalStateException(
                    "approver '" + approverId + "' is in tenant '" + approver.tenantId()
                            + "' but the review is for tenant '" + review.tenantId()
                            + "' — an approver may only approve its own tenant's review");
        }

        // (H3) author≠approver — from the server-recorded author, never a caller-supplied id.
        Optional<String> author = authors.authorFor(review.tenantId(), review.consequenceReviewHash());
        if (author.isPresent() && author.get().equals(approverId)) {
            throw new IllegalStateException(
                    "separation of duties: '" + approverId + "' authored this review and may not also "
                            + "approve it (author≠approver)");
        }

        // (C4.5) staleness: the diff must have been computed against the tenant's CURRENT active bundle.
        String active = activeBundles.activeBundleId(review.tenantId());
        Set<String> approverRolesForRecord = approver.roles();
        if (active == null || !active.equals(review.currentBundleId())) {
            throw new StaleReviewException(
                    "consequence review is stale: it was computed against current bundle '"
                            + review.currentBundleId() + "' but the tenant's active bundle is now '"
                            + active + "'. Recompute the diff against the new current bundle before approving.");
        }

        // Integrity: the review hash must actually be the hash of its own truth fields.
        String recomputed = review.recomputeHash();
        if (!recomputed.equals(review.consequenceReviewHash())) {
            throw new IllegalStateException(
                    "consequence review hash does not match its truth fields (expected " + recomputed
                            + ", was " + review.consequenceReviewHash() + ") — refusing to sign a tampered review");
        }

        ConsequenceApprovalRecord unsigned = new ConsequenceApprovalRecord(
                review.tenantId(),
                review.currentBundleId(),
                review.candidateBundleId(),
                review.fixtureSetHash(),
                review.consequenceReviewHash(),
                review.overPermissionAlarm(),
                approverId,
                approverRolesForRecord,
                decision,
                /* signature */ "",
                Instant.now());
        String signature = signer.sign(unsigned.signingPayload());
        return new ConsequenceApprovalRecord(
                unsigned.tenantId(), unsigned.currentBundleId(), unsigned.candidateBundleId(),
                unsigned.fixtureSetHash(), unsigned.consequenceReviewHash(), unsigned.overPermissionAlarm(),
                unsigned.approverId(), unsigned.approverRoles(), unsigned.decision(),
                signature, unsigned.signedAt());
    }

    /**
     * Whether a stored approval record authorizes promoting the given review's candidate. Requires an
     * APPROVE decision, an intact signature, and an EXACT match on every binding field (tenant, both
     * bundle ids, fixture set, and the review hash). Any truth change breaks this; display-wording
     * changes do not (they are not inputs to the hash).
     */
    public boolean authorizesPromotion(ConsequenceApprovalRecord record, ConsequenceReview review) {
        if (record.decision() != ApprovalDecision.APPROVE) {
            return false;
        }
        boolean tupleMatches = record.tenantId().equals(review.tenantId())
                && record.currentBundleId().equals(review.currentBundleId())
                && record.candidateBundleId().equals(review.candidateBundleId())
                && record.fixtureSetHash().equals(review.fixtureSetHash())
                && record.consequenceReviewHash().equals(review.consequenceReviewHash());
        if (!tupleMatches) {
            return false;
        }
        return signer.verify(record.signingPayload(), record.signature());
    }

    /** Deterministic, order-stable rendering of a role set for messages. */
    private static Set<String> sorted(Set<String> roles) {
        return new LinkedHashSet<>(new java.util.TreeSet<>(roles));
    }
}
