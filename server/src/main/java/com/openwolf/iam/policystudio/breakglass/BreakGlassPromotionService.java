package com.openwolf.iam.policystudio.breakglass;

import com.openwolf.iam.policystudio.ApprovalDecision;
import com.openwolf.iam.policystudio.CanonicalPolicyWriter;
import com.openwolf.iam.policystudio.ConsequenceApprovalRecord;
import com.openwolf.iam.policystudio.ConsequenceApprovalService;
import com.openwolf.iam.policystudio.ConsequenceReview;
import com.openwolf.iam.policystudio.GroundedStudioReviewService;
import com.openwolf.iam.policystudio.PolicyIR;
import com.openwolf.iam.policystudio.StudioGroundingProvider;
import com.openwolf.iam.policystudio.StudioGroundingSnapshot;
import com.openwolf.iam.policystudio.api.StudioSessionStore;
import com.openwolf.iam.policystudio.lifecycle.PolicyBundle;
import com.openwolf.iam.policystudio.lifecycle.PolicyPromotionService;
import com.openwolf.iam.policystudio.lifecycle.PromotionReceipt;
import com.openwolf.iam.policystudio.lifecycle.PromotionRecord;
import com.openwolf.iam.policystudio.lifecycle.PromotionRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.util.Set;

/**
 * S4 — the break-glass merge-and-promote spine. On two-person approval of a break-glass grant, this
 * service turns the grant into a REAL, content-addressed promotion that reaches the serving PDP (S1),
 * instead of leaving an in-memory {@code issued} flag with no runtime effect.
 *
 * <p>It reuses the ordinary C5 lifecycle end to end — no bespoke promotion path:
 * <ol>
 *   <li><b>Ground the tenant's current active bundle</b> ({@link StudioGroundingProvider}, S3) — the same
 *       server-derived vocabulary / base ceiling / <em>current restriction child</em> a normal review uses.</li>
 *   <li><b>Merge</b> the emergency tuple into that current child ({@link BreakGlassPolicyCompiler}) —
 *       additive: normal grants are preserved, only the granted tuple carries the time-boxed ALLOW/DENY
 *       pair. NOT a deny-all-else that would revoke normal access.</li>
 *   <li><b>Assemble + review</b> the merged candidate ({@link GroundedStudioReviewService}), recording the
 *       DRAFTER as the verified review author.</li>
 *   <li><b>Sign the approval</b> ({@link ConsequenceApprovalService}) as the APPROVER — which re-enforces
 *       two-person SoD (author≠approver, per C1/H3) on the expedited path, on top of the C6
 *       {@link BreakGlassApprovalService} gate the controller already ran.</li>
 *   <li><b>Promote</b> ({@link PolicyPromotionService}) — verify signature, re-validate, probe,
 *       compare-and-set the live pointer, and load the bundle into the Cerbos-watched runtime dir so the
 *       merged grant actually enforces. On expiry the emergency tuple's CEL DENY fires inside the PDP while
 *       the rest of the bundle stays intact.</li>
 * </ol>
 *
 * <p>Authoring-plane only — it composes existing authoring-plane services and never touches
 * runtime-enforcement code ({@code PolicyAuthoringBoundaryArchTest} guards the promotion service it calls).
 */
@Service
public class BreakGlassPromotionService {

    private static final Logger log = LoggerFactory.getLogger(BreakGlassPromotionService.class);

    private final StudioGroundingProvider grounding;
    private final GroundedStudioReviewService reviews;
    private final ConsequenceApprovalService approvals;
    private final PolicyPromotionService promotion;
    private final BreakGlassPolicyCompiler compiler;
    private final CanonicalPolicyWriter writer;

    public BreakGlassPromotionService(StudioGroundingProvider grounding,
                                      GroundedStudioReviewService reviews,
                                      ConsequenceApprovalService approvals,
                                      PolicyPromotionService promotion,
                                      BreakGlassPolicyCompiler compiler,
                                      CanonicalPolicyWriter writer) {
        this.grounding = grounding;
        this.reviews = reviews;
        this.approvals = approvals;
        this.promotion = promotion;
        this.compiler = compiler;
        this.writer = writer;
    }

    /**
     * Merge the approved break-glass grant into the tenant's current active bundle and promote the result
     * through C5, so the temporary grant loads into the serving PDP.
     *
     * @param pending       the doubly-gated grant awaiting issue (carries the VERIFIED drafter as author)
     * @param approverId    the VERIFIED approver identity (author≠approver is re-checked at signing)
     * @param approverRoles the approver's roles (an approver role is required to sign)
     * @param correlationId a correlation id for the promotion's idempotency key
     * @return the promotion receipt — a real content-addressed active version, not an in-memory flag
     */
    public PromotionReceipt mergeAndPromote(StudioSessionStore.PendingGrant pending,
                                            String approverId, Set<String> approverRoles, String correlationId) {
        BreakGlassGrant grant = pending.artifact().grant();
        String tenant = pending.tenantId();
        String drafter = pending.requestedBy();
        String kind = grant.resourceKind();

        // 1. Ground the tenant's ACTUAL current active bundle (S3) — vocabulary, ceiling, current child.
        StudioGroundingSnapshot snapshot = grounding.snapshot(tenant, kind);
        PolicyIR currentChild = snapshot.current().policy(); // null ⇒ tenant inherits the base ceiling

        // 2. MERGE the emergency tuple into the current child (additive) and materialise canonical YAML.
        PolicyIR merged = compiler.compile(grant, snapshot.baseCeiling(), currentChild);
        String mergedYaml = writer.write(merged);

        // 3. Review the merged candidate, recording the DRAFTER as the verified author (feeds author≠approver).
        ConsequenceReview review = reviews.assembleAndReview(tenant, drafter, kind, mergedYaml);

        // 4. Sign the approval as the APPROVER — re-enforces two-person SoD + approver role on this path.
        ConsequenceApprovalRecord approval =
                approvals.approve(review, approverId, approverRoles, ApprovalDecision.APPROVE);

        // 5. Build the immutable candidate bundle (same id the review was diffed for) and promote it.
        PolicyBundle candidate = reviews.assembleCandidateBundle(tenant, kind, mergedYaml, null);
        // Stable across retries, including a crash after promotion but before the C6 issuance ledger is
        // marked ACTIVATED. PolicyPromotionService replays this key without a second CAS.
        String idempotencyKey = "break-glass:" + pending.grantId();
        PromotionReceipt receipt = promotion.promote(new PromotionRequest(
                candidate, review, approval, idempotencyKey, PromotionRecord.Kind.PROMOTION));

        log.info("Break-glass grant '{}' promoted for tenant '{}': {} → {} (directory v{}) — emergency tuple "
                        + "({} / {}) merged into the active bundle, self-limiting at {}",
                pending.grantId(), tenant, receipt.fromBundleId(), receipt.toBundleId(),
                receipt.directoryVersion(), grant.action(), grant.role(), grant.expiresAt());
        return receipt;
    }
}
