package com.openwolf.iam.policystudio.lifecycle;

import com.openwolf.iam.policystudio.ConsequenceApprovalService;
import com.openwolf.iam.policystudio.GeneratedPolicyValidator;
import com.openwolf.iam.policystudio.PolicyAuthoringRequest;
import com.openwolf.iam.policystudio.PolicyIR;
import com.openwolf.iam.policystudio.PolicyParseException;
import com.openwolf.iam.policystudio.PolicyYamlParser;
import com.openwolf.iam.policystudio.TenantScope;
import com.openwolf.iam.tenancy.ActiveTenantDirectory;
import org.springframework.beans.factory.annotation.Autowired;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

/**
 * The one promotion machine for policy bundles (Axiom Story C5) — the SAME authorized compare-and-set
 * B4 uses to make a tenant visible, now advancing a tenant's active policy version from a reviewed OLD
 * bundle to a certified candidate. It is deliberately the same spine as the onboarding manifest
 * promotion (one machine, two artifact types): verify the approval signature over the exact C4
 * {@code consequenceReviewHash}, stage the candidate alongside the live version, load + probe every
 * invariant with {@code policyVersion = candidate bundleId}, then compare-and-set the live pointer on
 * B4's {@link ActiveTenantDirectory}. A failed signature, a tampered candidate, a stale CAS, or a failed
 * probe leaves the candidate INACTIVE.
 *
 * <p><b>Idempotent (C5.3, onboarding §10):</b> a lost-response retry with the same idempotency key finds
 * the existing PROMOTED receipt and returns it — it never drives a second CAS.
 *
 * <p><b>Rollback (§11):</b> not a database reversal — {@link #rollback} is a NEW authorized promotion to
 * a previously certified bundle. Old bundles remain immutable and available for the retention period.
 *
 * <p>Authoring-plane only: {@code PolicyAuthoringBoundaryArchTest} proves no runtime-enforcement code can
 * reach this service.
 */
@Service
public class PolicyPromotionService {

    private static final Logger log = LoggerFactory.getLogger(PolicyPromotionService.class);

    private final ActiveTenantDirectory directory;
    private final ConsequenceApprovalService approvals;
    private final PromotionRepository promotions;
    private final PolicyBundleRepository bundles;
    private final ApprovalRepository approvalStore;
    private final BundleCanonicalizer canonicalizer;
    private final GitCommitResolver gitResolver;
    private final CandidateProbe probe;
    private final GeneratedPolicyValidator validator;
    private final PolicyYamlParser parser;
    private final PromotionValidationContextProvider contextProvider;
    private final PromotedBundleLoader runtimeLoader;
    private final PromotionLedger ledger;
    private final PromotionExecutionLockStore executionLocks;

    @Autowired
    public PolicyPromotionService(ActiveTenantDirectory directory,
                                  ConsequenceApprovalService approvals,
                                  PromotionRepository promotions,
                                  PolicyBundleRepository bundles,
                                  ApprovalRepository approvalStore,
                                  BundleCanonicalizer canonicalizer,
                                  GitCommitResolver gitResolver,
                                  CandidateProbe probe,
                                  GeneratedPolicyValidator validator,
                                  PolicyYamlParser parser,
                                  PromotionValidationContextProvider contextProvider,
                                  PromotedBundleLoader runtimeLoader,
                                  PromotionLedger ledger,
                                  PromotionExecutionLockStore executionLocks) {
        this.directory = directory;
        this.approvals = approvals;
        this.promotions = promotions;
        this.bundles = bundles;
        this.approvalStore = approvalStore;
        this.canonicalizer = canonicalizer;
        this.gitResolver = gitResolver;
        this.probe = probe;
        this.validator = validator;
        this.parser = parser;
        this.contextProvider = contextProvider;
        this.runtimeLoader = runtimeLoader;
        this.ledger = ledger;
        this.executionLocks = executionLocks;
    }

    /** Direct constructor retained for pure lifecycle tests; production uses the proxied ledger. */
    public PolicyPromotionService(ActiveTenantDirectory directory,
                                  ConsequenceApprovalService approvals,
                                  PromotionRepository promotions,
                                  PolicyBundleRepository bundles,
                                  ApprovalRepository approvalStore,
                                  BundleCanonicalizer canonicalizer,
                                  GitCommitResolver gitResolver,
                                  CandidateProbe probe,
                                  GeneratedPolicyValidator validator,
                                  PolicyYamlParser parser,
                                  PromotionValidationContextProvider contextProvider,
                                  PromotedBundleLoader runtimeLoader) {
        this(directory, approvals, promotions, bundles, approvalStore, canonicalizer, gitResolver,
                probe, validator, parser, contextProvider, runtimeLoader,
                new PromotionLedger(directory, promotions, bundles, approvalStore),
                null);
    }

    /**
     * Promote a candidate bundle. Idempotent on the request's idempotency key.
     *
     * @throws UnauthorizedPromotionException if the approval does not authorize the exact candidate/review
     * @throws BundleTamperException          if the candidate fails its content-addressed integrity check
     * @throws StalePromotionException        if the active version drifted from the reviewed baseline (CAS)
     */
    public PromotionReceipt promote(PromotionRequest request) {
        String tenantId = request.tenantId();
        String candidateId = request.candidate().bundleId();
        if (executionLocks == null) {
            return promoteWithoutProductionFence(request, tenantId, candidateId);
        }
        try (PromotionExecutionLockStore.Lease lease = executionLocks.acquire(request.idempotencyKey())) {
            return promoteWithoutProductionFence(request, tenantId, candidateId, lease);
        }
    }

    private PromotionReceipt promoteWithoutProductionFence(PromotionRequest request,
                                                            String tenantId, String candidateId) {
        return promoteWithoutProductionFence(request, tenantId, candidateId, null);
    }

    private PromotionReceipt promoteWithoutProductionFence(PromotionRequest request,
                                                            String tenantId, String candidateId,
                                                            PromotionExecutionLockStore.Lease lease) {

        // ── Idempotency: a prior PROMOTED run replays; never a second CAS. ──
        PromotionRecord op = ledger.startOrResume(request);
        assertSameIntent(op, tenantId, request.reviewedCurrentBundleId(), candidateId,
                request.review().consequenceReviewHash(), request.approval().approverId(), request.kind());
        if (op.getStatus() == PromotionRecord.Status.PROMOTED) {
            log.info("Promotion (key {}) already PROMOTED {} → {} — idempotent replay",
                    request.idempotencyKey(), op.getFromBundleId(), op.getToBundleId());
            return receiptForReplay(op);
        }
        try {
            // ── 1. Authorize: signature over the EXACT C4 review hash + the exact candidate. ──
            if (!request.approval().candidateBundleId().equals(candidateId)) {
                throw new UnauthorizedPromotionException(
                        "approval authorizes candidate '" + request.approval().candidateBundleId()
                                + "' but the promotion candidate is '" + candidateId + "'");
            }
            // ── 1a. (H2) Recompute the consequence-review hash SERVER-SIDE from the review's own truth
            //        fields and reject a tampered hash — never trust the client-supplied hash field. ──
            String recomputed = request.review().recomputeHash();
            if (!recomputed.equals(request.review().consequenceReviewHash())) {
                throw new UnauthorizedPromotionException(
                        "consequence review hash does not match its truth fields (recomputed '" + recomputed
                                + "', request carried '" + request.review().consequenceReviewHash()
                                + "') — refusing to promote against a tampered review");
            }
            if (!approvals.authorizesPromotion(request.approval(), request.review())) {
                throw new UnauthorizedPromotionException(
                        "approval does not authorize this review (bad signature, non-APPROVE decision, or "
                                + "hash/tuple mismatch) — refusing to promote candidate '" + candidateId + "'");
            }

            // ── 2. The candidate must be certified over the exact matrix the approval covered. ──
            if (!request.candidate().testMetadata().fixtureSetHash().equals(request.review().fixtureSetHash())) {
                throw new UnauthorizedPromotionException(
                        "candidate bundle was certified over fixture set '"
                                + request.candidate().testMetadata().fixtureSetHash()
                                + "' but the approved review covered '" + request.review().fixtureSetHash() + "'");
            }

            // ── 3. Content-addressed integrity — a tampered candidate is rejected. ──
            request.candidate().verifyIntegrity(canonicalizer);
            assertFence(lease);

            // ── 3a. (H2) Re-run the deterministic GeneratedPolicyValidator UNCONDITIONALLY on the
            //        candidate (scope-containment, no-wildcard, base-ceiling totality). The grounding
            //        vocabulary + immutable ceiling come from a trusted server-side provider keyed off the
            //        bundle — NEVER from the promotion request. A candidate that was mutated or authored
            //        past the C2 gate is rejected here and stays INACTIVE. ──
            revalidate(request.candidate());

            // ── 4. Stage alongside live + load + probe every invariant at policyVersion = candidate id.
            //        The compile probe HARD-FAILS when the pinned Cerbos is unavailable (never
            //        version-stamp-only) — see StagingCandidateProbe. ──
            probe.verify(request.candidate());
            assertFence(lease);

            // ── 5. Publish to the serving runtime BEFORE changing the tenant-visible pointer. A promotion
            //        with no runtime backend is a configuration error, never a successful control-plane-only
            //        pointer flip. The publication barrier covers the blob poll / disk reload interval. ──
            if (!runtimeLoader.isConfigured()) {
                throw new PromotedBundleLoadException(candidateId, "<unconfigured>",
                        new IllegalStateException("no runtime policy backend configured"));
            }
            runtimeLoader.load(request.candidate());
            runtimeLoader.awaitPublication(request.candidate());
            assertFence(lease);

            // ── 6. Compare-and-set the live pointer from the reviewed OLD id to the already-published
            //        candidate. Until this atomic step completes every request stays on the old version. ──
            // ── 7. Persist the immutable bundle record + signed approval + active receipt in one
            // short transaction. No external call is made by this ledger boundary. ──
            // Resolve the source anchor before opening the short CAS/ledger transaction. The production
            // resolver may invoke git and must never run while the final DB transaction is held.
            String gitCommit = gitResolver.currentCommit();
            assertFence(lease);
            long directoryVersion = ledger.compareAndPromote(request, op, gitCommit);
            log.info("Promoted tenant '{}' {} → {} (kind={}, directory v{})",
                    tenantId, request.reviewedCurrentBundleId(), candidateId, request.kind(), directoryVersion);
            return new PromotionReceipt(op.getId(), tenantId, request.reviewedCurrentBundleId(),
                    candidateId, directoryVersion, request.kind(), false);

        } catch (RuntimeException e) {
            ledger.markFailed(op, e);
            log.warn("FAIL-CLOSED: promotion of candidate '{}' for tenant '{}' failed — candidate stays "
                    + "INACTIVE: {}", candidateId, tenantId, e.toString());
            throw e;
        }
    }

    private static void assertFence(PromotionExecutionLockStore.Lease lease) {
        if (lease != null) lease.assertOwned();
    }

    /**
     * (H2) Re-run the deterministic generation gate on the candidate's tenant restriction child policies.
     * The vocabulary + author scope + immutable base ceiling come from a trusted {@link
     * PromotionValidationContextProvider} keyed off the bundle (fail-closed if none) — the request cannot
     * supply a looser ceiling. Every non-root {@code resourcePolicy} in the bundle is parsed and validated;
     * base/derived-role files (which the studio parser rejects as non-resource-policy) are skipped — they
     * are the ceiling, not the child being narrowed. A single violation aborts the promotion.
     */
    private void revalidate(PolicyBundle candidate) {
        List<String> violations = new ArrayList<>();
        int childrenValidated = 0;
        for (BundleFile file : candidate.renderedFiles()) {
            // S3: a self-contained bundle also captures the immutable base scope-chain (e.g. the tenant
            // `default` scope policy) verbatim — those are the CEILING, not the authored tenant restriction
            // child, and must not be re-validated against the author's subtree. The authored child is the
            // only file carrying the `resource@tenant` marker (see materializeCandidate); base ceiling /
            // derived-role / variable files never do. Re-validate ONLY the authored child(ren).
            if (!file.path().contains("@" + candidate.tenantId())) {
                continue;
            }
            PolicyIR ir;
            try {
                ir = parser.parse(file.yaml());
            } catch (PolicyParseException notAResourcePolicy) {
                // A base ceiling / derived-role / variable file — not a tenant restriction child. The
                // wildcard/scope/totality invariants live on the child; skip non-child files.
                continue;
            }
            TenantScope scope;
            try {
                scope = TenantScope.of(ir.scope());
            } catch (IllegalArgumentException badScope) {
                violations.add("file '" + file.path() + "' has an invalid scope: " + badScope.getMessage());
                continue;
            }
            if (scope.isRoot()) {
                continue; // the root ceiling policy, not a tenant child
            }
            childrenValidated++;
            // Resolve trusted grounding independently for this parsed child. One tenant-wide bundle can
            // contain agent, relationship, domain, and Policy Studio children; a context selected from the
            // first child is not a valid ceiling for the remaining resource kinds.
            PromotionValidationContext ctx = contextProvider.contextFor(
                    candidate, ir.resource(), ir.scope());
            PolicyAuthoringRequest req = new PolicyAuthoringRequest(
                    "promotion re-validation of bundle " + candidate.bundleId(),
                    ctx.vocabulary(), ctx.authorScope(), ctx.subscopesEnabled(), ctx.baseCeiling());
            GeneratedPolicyValidator.Result result = validator.validate(ir, req);
            if (!result.accepted()) {
                for (String v : result.violations()) {
                    violations.add("file '" + file.path() + "': " + v);
                }
            }
        }
        if (childrenValidated == 0) {
            violations.add("candidate carries no tenant-child resource policy for tenant '"
                    + candidate.tenantId() + "'");
        }
        if (!violations.isEmpty()) {
            throw new PolicyRevalidationException(candidate.bundleId(), violations);
        }
        log.debug("Candidate '{}' re-validated OK ({} tenant-child polic(ies))",
                candidate.bundleId(), childrenValidated);
    }

    /**
     * Roll back to a previously certified bundle (§11) — a NEW authorized promotion, never a delete or a
     * DB reversal. The {@code priorBundle} must still exist in the immutable store; the caller supplies a
     * fresh approval over a rollback review whose current is the now-active bundle and whose candidate is
     * the prior bundle.
     */
    public PromotionReceipt rollback(PromotionRequest rollbackRequest) {
        if (!bundles.existsById(rollbackRequest.candidate().bundleId())) {
            throw new UnauthorizedPromotionException(
                    "rollback target bundle '" + rollbackRequest.candidate().bundleId()
                            + "' is not in the immutable store — rollback restores a previously certified bundle");
        }
        return promote(new PromotionRequest(
                rollbackRequest.candidate(), rollbackRequest.review(), rollbackRequest.approval(),
                rollbackRequest.idempotencyKey(), PromotionRecord.Kind.ROLLBACK));
    }

    /**
     * Replay a completed operation before creating a fresh approval. This is the lost-response path:
     * the active pointer has already advanced, so re-running the approval staleness gate would reject a
     * legitimate retry. Every trusted intent field is bound before returning the receipt.
     */
    @Transactional(readOnly = true)
    public Optional<PromotionReceipt> replayCompleted(String idempotencyKey, String tenantId,
                                                       String fromBundleId, String toBundleId,
                                                       String consequenceReviewHash, String approverId,
                                                       PromotionRecord.Kind kind) {
        if (idempotencyKey == null || idempotencyKey.isBlank()) {
            throw new IllegalArgumentException("idempotencyKey must be set");
        }
        PromotionRecord op = promotions.findByIdempotencyKey(idempotencyKey).orElse(null);
        if (op == null) {
            return Optional.empty();
        }
        assertSameIntent(op, tenantId, fromBundleId, toBundleId, consequenceReviewHash, approverId, kind);
        return op.getStatus() == PromotionRecord.Status.PROMOTED
                ? Optional.of(receiptForReplay(op))
                : Optional.empty();
    }

    private static void assertSameIntent(PromotionRecord op, String tenantId, String fromBundleId,
                                         String toBundleId, String consequenceReviewHash,
                                         String approverId, PromotionRecord.Kind kind) {
        if (!op.getTenantId().equals(tenantId)
                || !java.util.Objects.equals(op.getFromBundleId(), fromBundleId)
                || !op.getToBundleId().equals(toBundleId)
                || !op.getConsequenceReviewHash().equals(consequenceReviewHash)
                || !op.getApproverId().equals(approverId)
                || op.getKind() != kind) {
            throw new UnauthorizedPromotionException("idempotency key '" + op.getIdempotencyKey()
                    + "' is already bound to a different tenant, kind, approver, candidate, baseline, or review");
        }
    }

    private PromotionReceipt receiptForReplay(PromotionRecord op) {
        long v = op.getDirectoryVersion() == null ? 0L : op.getDirectoryVersion();
        return new PromotionReceipt(op.getId(), op.getTenantId(), op.getFromBundleId(),
                op.getToBundleId(), v, op.getKind(), true);
    }
}
