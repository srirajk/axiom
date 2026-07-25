package com.openwolf.iam.policystudio.api;

import com.openwolf.iam.policystudio.ApprovalDecision;
import com.openwolf.iam.policystudio.ConsequenceApprovalRecord;
import com.openwolf.iam.policystudio.ConsequenceApprovalService;
import com.openwolf.iam.policystudio.ConsequenceReview;
import com.openwolf.iam.policystudio.lifecycle.PolicyBundle;
import com.openwolf.iam.policystudio.lifecycle.PolicyPromotionService;
import com.openwolf.iam.policystudio.lifecycle.PromotionReceipt;
import com.openwolf.iam.policystudio.lifecycle.PromotionRecord;
import com.openwolf.iam.policystudio.lifecycle.PromotionRequest;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Set;

/**
 * The C5 promotion WRITE surface — the marquee approve+promote flow. It composes two existing services
 * with zero new policy logic:
 *
 * <ol>
 *   <li>{@link ConsequenceApprovalService#approve} signs the human approval over the exact C4
 *       {@code consequenceReviewHash} (fails closed on a stale or tampered review);</li>
 *   <li>{@link PolicyPromotionService#promote} verifies that signature, stages + probes the candidate,
 *       and compare-and-sets the tenant's live policy pointer.</li>
 * </ol>
 *
 * <p><b>The C1 meta-authz is enforced here, at the API — all identity is VERIFIED, never a body field:</b>
 * <ul>
 *   <li><b>approver role</b> — {@code @PreAuthorize hasRole('policy_approver')};</li>
 *   <li><b>approver identity</b> — the authenticated {@code sub}. A null/absent principal fails closed
 *       ({@link StudioPrincipal#actor} throws), never skips the check;</li>
 *   <li><b>author≠approver</b> — the author is the VERIFIED identity that computed the referenced C4
 *       review (recorded server-side at {@code POST /reviews} time, never supplied in this request). The
 *       review is looked up by {@code reviewId} in the tenant-scoped store and a miss FAILS CLOSED (403).
 *       The approver may not be that author; this holds <em>regardless of role</em>, so a
 *       {@code platform_admin} is never an auto-approver of their own draft (C1.2/C1.3) → 409;</li>
 *   <li><b>tenant scope</b> — the principal's {@code tenant_id} claim. The review lookup is tenant-scoped
 *       (another tenant's reviewId resolves as not-found ⇒ fail closed) and the candidate's tenant must
 *       match. Tenant is NEVER read from a body field.</li>
 * </ul>
 *
 * <p><b>Server-side hash re-verification:</b> {@link ConsequenceApprovalService#approve} recomputes the
 * consequence-review hash from the review's truth fields and refuses to sign a tampered review, and blocks
 * a stale review (the active bundle drifted). {@link PolicyPromotionService#promote} (H2) additionally
 * re-runs {@code GeneratedPolicyValidator} unconditionally on the candidate, recomputes the review hash
 * server-side, and hard-fails when the pinned Cerbos is unavailable (never version-stamp-only).
 */
@RestController
@RequestMapping("/admin/studio")
@PreAuthorize("hasRole('policy_approver')")
public class StudioPromotionController {

    private final ConsequenceApprovalService approvals;
    private final PolicyPromotionService promotion;
    private final StudioSessionStore store;

    public StudioPromotionController(ConsequenceApprovalService approvals, PolicyPromotionService promotion,
                                     StudioSessionStore store) {
        this.approvals = approvals;
        this.promotion = promotion;
        this.store = store;
    }

    /**
     * The promotion request the SPA posts. {@code reviewId} references a C4 review previously computed by
     * {@code POST /reviews} (which recorded the verified author + tenant + the trusted review itself) — the
     * review, author, and candidate are NOT taken from this body. The exact reviewed candidate is loaded
     * from the tenant-scoped server store.
     */
    public record PromotePayload(String reviewId, String idempotencyKey) {}

    /** {@code POST /admin/studio/promotions} — approve (sign) the review, then promote the candidate. */
    @PostMapping("/promotions")
    public ResponseEntity<PromotionReceipt> promote(@RequestBody PromotePayload payload, Authentication auth) {
        return ResponseEntity.ok(execute(payload, auth, PromotionRecord.Kind.PROMOTION));
    }

    /**
     * {@code POST /admin/studio/rollbacks} — roll back to a previously certified bundle. A rollback is a
     * NEW authorized promotion (never a delete/DB reversal); the {@code candidate} is the prior bundle to
     * restore and the same approve+SoD+CAS rules apply.
     */
    @PostMapping("/rollbacks")
    public ResponseEntity<PromotionReceipt> rollback(@RequestBody PromotePayload payload, Authentication auth) {
        return ResponseEntity.ok(execute(payload, auth, PromotionRecord.Kind.ROLLBACK));
    }

    private PromotionReceipt execute(PromotePayload payload, Authentication auth, PromotionRecord.Kind kind) {
        if (payload == null || payload.reviewId() == null || payload.idempotencyKey() == null
                || payload.idempotencyKey().isBlank()) {
            throw new IllegalArgumentException("reviewId and idempotencyKey are required");
        }
        // Verified identity only — a null/absent principal fails closed here (never skips the SoD check).
        String approver = StudioPrincipal.actor(auth);
        String tenant = StudioPrincipal.tenant(auth);
        Set<String> approverRoles = StudioPrincipal.roles(auth);

        // Look up the trusted, server-recorded review (tenant-scoped): a miss (wrong tenant / unknown /
        // never computed here) FAILS CLOSED — you cannot promote a review the server never produced.
        StudioSessionStore.StoredReview stored = store.getReview(tenant, payload.reviewId())
                .orElseThrow(() -> new CrossTenantException(
                        "no consequence review '" + payload.reviewId() + "' for tenant '" + tenant
                                + "' — compute the review first; promotion binds to the server's own review record"));
        ConsequenceReview review = stored.review();
        PolicyBundle candidate = stored.candidate();
        String author = stored.authorId(); // the VERIFIED drafter identity captured at compute time

        // Tenant scope: never from the body — the review (already tenant-scoped) and candidate must match.
        StudioPrincipal.assertSameTenant(tenant, review.tenantId());
        StudioPrincipal.assertSameTenant(tenant, candidate.tenantId());

        // C1.2/C1.3 author≠approver — VERIFIED author vs VERIFIED approver, regardless of role
        // (platform_admin is not an auto-approver of its own draft).
        if (author != null && author.equals(approver)) {
            throw new SeparationOfDutiesException(
                    "separation of duties: '" + approver + "' computed this review and may not also approve/"
                            + "promote it (author≠approver)");
        }

        // Lost-response retry: authorize tenant/role/SoD and bind the global key to this exact trusted
        // handoff before replaying. Do this before approval because the active baseline already moved.
        java.util.Optional<PromotionReceipt> replay = promotion.replayCompleted(
                payload.idempotencyKey(), tenant, review.currentBundleId(), candidate.bundleId(),
                review.consequenceReviewHash(), approver, kind);
        if (replay.isPresent()) {
            store.markReviewCompleted(stored);
            return replay.get();
        }

        // (1) sign the approval over the exact C4 review hash — approve() recomputes the hash from the
        //     review's truth fields and refuses a tampered/stale review (server-side re-verification).
        ConsequenceApprovalRecord approval =
                approvals.approve(review, approver, approverRoles, ApprovalDecision.APPROVE);

        // (2) promote: verify signature, stage + probe candidate, CAS the live pointer.
        PromotionRequest request = new PromotionRequest(
                candidate, review, approval, payload.idempotencyKey(), kind);
        PromotionReceipt receipt = kind == PromotionRecord.Kind.ROLLBACK
                ? promotion.rollback(request)
                : promotion.promote(request);
        // Keep failed attempts available to another approver/retry. Retire only after activation succeeds.
        store.markReviewCompleted(stored);
        return receipt;
    }
}
