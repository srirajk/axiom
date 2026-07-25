package com.openwolf.iam.policystudio.lifecycle;

import com.openwolf.iam.policystudio.ApprovalDecision;
import com.openwolf.iam.policystudio.BaseCeiling;
import com.openwolf.iam.policystudio.BundleSnapshot;
import com.openwolf.iam.policystudio.ConsequenceApprovalRecord;
import com.openwolf.iam.policystudio.ConsequenceApprovalService;
import com.openwolf.iam.policystudio.ConsequenceDiffService;
import com.openwolf.iam.policystudio.ConsequenceFixtureMatrix;
import com.openwolf.iam.policystudio.ConsequenceReview;
import com.openwolf.iam.policystudio.ConsequenceReviewSigner;
import com.openwolf.iam.policystudio.FixtureCell;
import com.openwolf.iam.policystudio.GeneratedPolicyValidator;
import com.openwolf.iam.policystudio.InMemoryTenantActiveBundleRegistry;
import com.openwolf.iam.policystudio.ManifestVocabulary;
import com.openwolf.iam.policystudio.PdpDecisionSource;
import com.openwolf.iam.policystudio.PolicyExpectationEvaluator;
import com.openwolf.iam.policystudio.ConditionEvaluator;
import com.openwolf.iam.policystudio.LocalPdpDecisionSource;
import com.openwolf.iam.policystudio.PolicyYamlParser;
import com.openwolf.iam.policystudio.TenantScope;
import com.openwolf.iam.tenancy.ActiveTenantDirectory;
import com.openwolf.iam.tenancy.ActiveTenantRepository;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Deterministic fixtures for the Axiom Story C5 lifecycle harness. It bridges the C4 consequence-diff
 * machinery (real PDP decisions via the in-process fidelity evaluator — no LLM, no Docker) to the C5
 * immutable full-bundle model, and stamps the C4 review's bundle ids with the C5 content-addressed ids
 * so an approval binds, the CAS aligns, and the examiner joins on ONE identity end to end.
 */
final class C5LifecycleFixtures {

    private C5LifecycleFixtures() {}

    static final String TENANT = "acme";
    static final String SIGNING_KEY = "c5-test-consequence-signing-key";
    static final List<String> MANIFEST_REFS = List.of("manifest:agent@sha-abc123");

    // ── C4 policy bodies (version "default") reused for the real-PDP diff ─────────────────────────

    static String currentBody() {
        return """
                apiVersion: api.cerbos.dev/v1
                resourcePolicy:
                  version: "default"
                  resource: agent
                  scope: "acme"
                  scopePermissions: SCOPE_PERMISSIONS_REQUIRE_PARENTAL_CONSENT_FOR_ALLOWS
                  rules:
                    - actions: ["invoke", "invoke_membership", "register", "deregister"]
                      effect: EFFECT_ALLOW
                      roles: ["platform_admin"]
                    - actions: ["invoke", "invoke_membership"]
                      effect: EFFECT_ALLOW
                      roles: ["domain_admin"]
                    - actions: ["register", "deregister"]
                      effect: EFFECT_ALLOW
                      roles: ["domain_admin"]
                    - actions: ["invoke", "invoke_membership"]
                      effect: EFFECT_DENY
                      roles: ["chat_user", "relationship_manager"]
                """;
    }

    static String candidateBody() {
        return """
                apiVersion: api.cerbos.dev/v1
                resourcePolicy:
                  version: "default"
                  resource: agent
                  scope: "acme"
                  scopePermissions: SCOPE_PERMISSIONS_REQUIRE_PARENTAL_CONSENT_FOR_ALLOWS
                  rules:
                    - actions: ["invoke", "invoke_membership", "register", "deregister"]
                      effect: EFFECT_ALLOW
                      roles: ["platform_admin"]
                    - actions: ["invoke", "invoke_membership"]
                      effect: EFFECT_ALLOW
                      roles: ["domain_admin"]
                    - actions: ["register", "deregister"]
                      effect: EFFECT_DENY
                      roles: ["domain_admin"]
                    - actions: ["invoke", "invoke_membership"]
                      effect: EFFECT_ALLOW
                      roles: ["chat_user", "relationship_manager"]
                """;
    }

    static BundleCanonicalizer canon() {
        return new BundleCanonicalizer();
    }

    // ── manifest vocabulary + base ceiling for the `agent` resource (grounded in the base bundle) ──

    static ManifestVocabulary vocab() {
        return new ManifestVocabulary(
                "agent",
                Set.of("invoke", "invoke_membership", "register", "deregister"),
                Set.of("internal", "confidential", "confidential-pii"),
                Set.of("domain", "audience", "access_mode", "data_classification",
                        "segments", "admin_domains", "domains", "tenant_id"),
                Set.of("platform_admin", "domain_admin", "chat_user", "relationship_manager", "conduit_admin"),
                Set.of("business_derived_roles"));
    }

    static BaseCeiling agentCeiling() {
        return new BaseCeiling(
                "agent",
                Set.of(
                        new BaseCeiling.Tuple("invoke", "platform_admin"),
                        new BaseCeiling.Tuple("invoke_membership", "platform_admin"),
                        new BaseCeiling.Tuple("register", "platform_admin"),
                        new BaseCeiling.Tuple("deregister", "platform_admin"),
                        new BaseCeiling.Tuple("invoke", "domain_admin"),
                        new BaseCeiling.Tuple("invoke_membership", "domain_admin"),
                        new BaseCeiling.Tuple("register", "domain_admin"),
                        new BaseCeiling.Tuple("deregister", "domain_admin"),
                        new BaseCeiling.Tuple("invoke", "chat_user"),
                        new BaseCeiling.Tuple("invoke", "relationship_manager"),
                        new BaseCeiling.Tuple("invoke_membership", "chat_user"),
                        new BaseCeiling.Tuple("invoke_membership", "relationship_manager")),
                true,
                Set.of("agent@"));
    }

    static PdpDecisionSource localPdp() {
        return new LocalPdpDecisionSource(new PolicyExpectationEvaluator(new ConditionEvaluator()));
    }

    static ConsequenceDiffService diffService() {
        return new ConsequenceDiffService();
    }

    // ── the sampled matrix (same as C4; same-tenant cells, fully decidable) ────────────────────────

    private static FixtureCell cell(Set<String> roles, String action, String label) {
        return new FixtureCell(roles, TENANT, Map.of(), TENANT, Map.of(), action, label);
    }

    static ConsequenceFixtureMatrix matrix() {
        return ConsequenceFixtureMatrix.of(List.of(
                cell(Set.of("chat_user"), "invoke", "chatUser_invoke"),
                cell(Set.of("chat_user"), "invoke_membership", "chatUser_membership"),
                cell(Set.of("relationship_manager"), "invoke", "rm_invoke"),
                cell(Set.of("domain_admin"), "register", "domainAdmin_register"),
                cell(Set.of("platform_admin"), "invoke", "platformAdmin_invoke")));
    }

    /** The sampled matrix hash — what a bundle's certifying test metadata must carry to be promotable. */
    static String matrixHash() {
        return matrix().fixtureSetHash();
    }

    // ── C5 immutable full bundle (version sentinel form) ──────────────────────────────────────────

    /** Convert a C4 body (version "default") into the C5 sentinel-versioned file body. */
    static String toSentinelBody(String c4Body) {
        return c4Body.replace("version: \"default\"",
                "version: " + BundleCanonicalizer.BUNDLE_VERSION_SENTINEL);
    }

    static BundleTestMetadata testMetadata(String fixtureSetHash) {
        return new BundleTestMetadata(fixtureSetHash, matrix().cells().size(), "c3-independent-oracle",
                localPdp().sourceId());
    }

    /** A C5 immutable bundle from a C4 body; its {@code b_} id is derived from the full canonical bytes. */
    static PolicyBundle bundle(String c4Body, String fixtureSetHash) {
        BundleFile file = new BundleFile("agent@acme.yaml", toSentinelBody(c4Body));
        return PolicyBundle.materialize(TENANT, List.of(file), MANIFEST_REFS,
                testMetadata(fixtureSetHash), canon());
    }

    /** A C4 snapshot for the real-PDP diff, STAMPED with the given C5 bundle id (one identity end to end). */
    static BundleSnapshot snapshotStamped(String c4Body, String stampId) {
        var ir = new PolicyYamlParser().parse(c4Body);
        return new BundleSnapshot(stampId, ir, agentCeiling(), c4Body);
    }

    /** Compute the C4 consequence review between two bundles (each with its own body), using the C5 ids. */
    static ConsequenceReview reviewBetween(PolicyBundle cur, String curBody, PolicyBundle cand, String candBody) {
        return diffService().computeReview(TENANT, vocab(),
                snapshotStamped(curBody, cur.bundleId()), snapshotStamped(candBody, cand.bundleId()),
                matrix(), localPdp());
    }

    /** The forward diff: current (currentBody) → candidate (candidateBody). */
    static ConsequenceReview review(PolicyBundle current, PolicyBundle candidate) {
        return reviewBetween(current, currentBody(), candidate, candidateBody());
    }

    /**
     * A self-consistent review binding two C5 bundle ids WITHOUT running the diff (so it works for
     * structurally-bad candidates the PDP evaluator would choke on). Empty delta; the hash is recomputed
     * from the truth fields so it passes the promotion's server-side hash re-check.
     */
    static ConsequenceReview handReview(PolicyBundle current, PolicyBundle candidate) {
        String fs = candidate.testMetadata().fixtureSetHash();
        ConsequenceReview tmp = new ConsequenceReview(TENANT, "agent", current.bundleId(), candidate.bundleId(),
                fs, List.of(), false, 0, "[]", "PLACEHOLDER", null, null, now(), null);
        return new ConsequenceReview(TENANT, "agent", current.bundleId(), candidate.bundleId(),
                fs, List.of(), false, 0, "[]", tmp.recomputeHash(), null, null, now(), null);
    }

    /** A review whose {@code consequenceReviewHash} does NOT match its truth fields (H2 tamper). */
    static ConsequenceReview tamperedReview(PolicyBundle current, PolicyBundle candidate) {
        String fs = candidate.testMetadata().fixtureSetHash();
        return new ConsequenceReview(TENANT, "agent", current.bundleId(), candidate.bundleId(),
                fs, List.of(), false, 0, "[]", "crh-TAMPERED-does-not-match", null, null, now(), null);
    }

    static ConsequenceReviewSigner signer() {
        return ConsequenceReviewSigner.withKey(SIGNING_KEY);
    }

    /** Sign an APPROVE bound to the exact review (current bundle must be the registry's active bundle). */
    static ConsequenceApprovalRecord approve(ConsequenceReview review, String approver) {
        InMemoryTenantActiveBundleRegistry reg = new InMemoryTenantActiveBundleRegistry();
        reg.setActiveBundle(TENANT, review.currentBundleId());
        ConsequenceApprovalService approvals = new ConsequenceApprovalService(signer(), reg);
        return approvals.approve(review, approver, Set.of("security_reviewer"), ApprovalDecision.APPROVE);
    }

    static ConsequenceApprovalService approvalService() {
        // authorizesPromotion does not read the registry, so any registry is fine here.
        return new ConsequenceApprovalService(signer(), new InMemoryTenantActiveBundleRegistry());
    }

    // ── stateful in-memory repositories (Mockito, the B4 idiom) ───────────────────────────────────

    static PromotionRepository promotionRepo() {
        Map<String, PromotionRecord> byKey = new java.util.concurrent.ConcurrentHashMap<>();
        Map<String, PromotionRecord> byId = new java.util.concurrent.ConcurrentHashMap<>();
        PromotionRepository repo = mock(PromotionRepository.class);
        when(repo.findByIdempotencyKey(anyString()))
                .thenAnswer(a -> java.util.Optional.ofNullable(byKey.get(a.<String>getArgument(0))));
        when(repo.findByIdempotencyKeyForUpdate(anyString()))
                .thenAnswer(a -> java.util.Optional.ofNullable(byKey.get(a.<String>getArgument(0))));
        when(repo.save(any(PromotionRecord.class))).thenAnswer(a -> {
            PromotionRecord r = a.getArgument(0);
            byKey.put(r.getIdempotencyKey(), r);
            byId.put(r.getId(), r);
            return r;
        });
        when(repo.findByTenantIdOrderByCreatedAtDesc(anyString())).thenAnswer(a -> byId.values().stream()
                .filter(r -> r.getTenantId().equals(a.<String>getArgument(0))).toList());
        return repo;
    }

    static PolicyBundleRepository bundleRepo() {
        Map<String, PolicyBundleRecord> byId = new java.util.concurrent.ConcurrentHashMap<>();
        PolicyBundleRepository repo = mock(PolicyBundleRepository.class);
        when(repo.save(any(PolicyBundleRecord.class))).thenAnswer(a -> {
            PolicyBundleRecord r = a.getArgument(0);
            byId.put(r.getBundleId(), r);
            return r;
        });
        when(repo.findById(anyString()))
                .thenAnswer(a -> java.util.Optional.ofNullable(byId.get(a.<String>getArgument(0))));
        when(repo.existsById(anyString())).thenAnswer(a -> byId.containsKey(a.<String>getArgument(0)));
        when(repo.findByTenantIdOrderByCreatedAtDesc(anyString())).thenAnswer(a -> byId.values().stream()
                .filter(r -> r.getTenantId().equals(a.<String>getArgument(0))).toList());
        return repo;
    }

    static ApprovalRepository approvalRepo() {
        Map<String, ApprovalRecordEntity> byId = new java.util.concurrent.ConcurrentHashMap<>();
        ApprovalRepository repo = mock(ApprovalRepository.class);
        when(repo.save(any(ApprovalRecordEntity.class))).thenAnswer(a -> {
            ApprovalRecordEntity r = a.getArgument(0);
            byId.put(r.getId(), r);
            return r;
        });
        when(repo.findByCandidateBundleId(anyString())).thenAnswer(a -> byId.values().stream()
                .filter(r -> r.getCandidateBundleId().equals(a.<String>getArgument(0))).toList());
        return repo;
    }

    static ApplicationAuditRepository auditRepo() {
        Map<String, ApplicationAuditEntry> byId = new java.util.concurrent.ConcurrentHashMap<>();
        ApplicationAuditRepository repo = mock(ApplicationAuditRepository.class);
        when(repo.save(any(ApplicationAuditEntry.class))).thenAnswer(a -> {
            ApplicationAuditEntry r = a.getArgument(0);
            byId.put(r.getId(), r);
            return r;
        });
        when(repo.findByCerbosCallId(anyString())).thenAnswer(a -> byId.values().stream()
                .filter(r -> r.getCerbosCallId().equals(a.<String>getArgument(0))).toList());
        when(repo.findByTransactionIdOrderByOccurredAt(anyString())).thenAnswer(a -> byId.values().stream()
                .filter(r -> r.getTransactionId().equals(a.<String>getArgument(0))).toList());
        return repo;
    }

    static CerbosDecisionRepository decisionRepo() {
        Map<String, CerbosDecisionEntry> byId = new java.util.concurrent.ConcurrentHashMap<>();
        CerbosDecisionRepository repo = mock(CerbosDecisionRepository.class);
        when(repo.save(any(CerbosDecisionEntry.class))).thenAnswer(a -> {
            CerbosDecisionEntry r = a.getArgument(0);
            byId.put(r.getCerbosCallId(), r);
            return r;
        });
        when(repo.findById(anyString()))
                .thenAnswer(a -> java.util.Optional.ofNullable(byId.get(a.<String>getArgument(0))));
        return repo;
    }

    /** A probe that always passes — the deterministic seam for tests that are not exercising the probe. */
    static CandidateProbe passingProbe() {
        return candidate -> { /* no-op: version-stamping/compile invariants covered by their own test */ };
    }

    /** A probe that always hard-fails — models the mandatory cerbos-compile probe on a Cerbos-down host. */
    static CandidateProbe cerbosDownProbe() {
        return candidate -> {
            throw new IllegalStateException("cerbos compile probe is MANDATORY for promotion but no pinned "
                    + "Cerbos is available — refusing to promote candidate '" + candidate.bundleId() + "'");
        };
    }

    /** The H2 re-validation grounding: the `agent` vocabulary + immutable ceiling at author scope `acme`. */
    static PromotionValidationContextProvider validationProvider() {
        return (candidate, resourceKind, childScope) -> {
            if (!"agent".equals(resourceKind)) {
                throw new IllegalStateException("fixture has no grounding for resource kind '"
                        + resourceKind + "'");
            }
            return new PromotionValidationContext(vocab(), TenantScope.of("acme"), false, agentCeiling());
        };
    }

    static GeneratedPolicyValidator validator() {
        return new GeneratedPolicyValidator();
    }

    /** A deterministic git resolver. */
    static GitCommitResolver gitResolver(String commit) {
        return () -> commit;
    }

    static ActiveTenantRepository activeRepo() {
        return mock(ActiveTenantRepository.class);
    }

    /** A fresh B4 directory (in-memory snapshot; save/deleteById are no-op mocks). */
    static ActiveTenantDirectory directory() {
        return new ActiveTenantDirectory(activeRepo());
    }

    /** Build the promotion service over the given directory + repos (fixture re-validation provider). */
    static PolicyPromotionService promotionService(ActiveTenantDirectory dir, PromotionRepository pr,
                                                   PolicyBundleRepository br, ApprovalRepository ar,
                                                   CandidateProbe probe, String gitCommit) {
        return new PolicyPromotionService(dir, approvalService(), pr, br, ar, canon(),
                gitResolver(gitCommit), probe, validator(), new PolicyYamlParser(), validationProvider(),
                configuredTestLoader());
    }

    private static PromotedBundleLoader configuredTestLoader() {
        try {
            return new PromotedBundleLoader(java.nio.file.Files.createTempDirectory("c5-runtime-").toString(), 0L, 1);
        } catch (java.io.IOException e) {
            throw new IllegalStateException("could not create C5 runtime fixture directory", e);
        }
    }

    static Instant now() {
        return Instant.parse("2026-07-17T00:00:00Z");
    }
}
