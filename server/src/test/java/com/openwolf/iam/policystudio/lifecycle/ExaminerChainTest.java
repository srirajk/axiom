package com.openwolf.iam.policystudio.lifecycle;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.openwolf.iam.policystudio.ConsequenceApprovalRecord;
import com.openwolf.iam.policystudio.ConsequenceProseModelClient;
import com.openwolf.iam.policystudio.ConsequenceReview;
import com.openwolf.iam.policystudio.ConsequenceReviewSigner;
import com.openwolf.iam.policystudio.PolicyAuthoringModelClient;
import com.openwolf.iam.tenancy.ActiveTenantDirectory;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Field;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * C5.1 / C5.6 (headline) — the examiner chain is reconstructed from IMMUTABLE records with the LLM
 * subsystem structurally DISABLED. For a recorded decision it joins application audit
 * (cerbosCallId + activePolicyVersion) → Cerbos decision entry → immutable bundle record → Git commit →
 * approvals/tests, with every cross-check (version match, bundle integrity, signature-valid APPROVE,
 * present Git anchor + test metadata) holding. A missing call id, a mismatched version, or a broken join
 * is an audit-integrity FAILURE, not a warning. The reconstruction touches no model of any kind.
 */
class ExaminerChainTest {

    private static final ObjectMapper JSON = new ObjectMapper();

    @Test
    void answeredFromImmutableRecordsNoLlm() throws Exception {
        // ── Seed a fully promoted bundle end to end (real C4 diff + signed approval; no LLM, no Docker). ──
        PolicyBundle current = C5LifecycleFixtures.bundle(C5LifecycleFixtures.currentBody(), C5LifecycleFixtures.matrixHash());
        PolicyBundle candidate = C5LifecycleFixtures.bundle(C5LifecycleFixtures.candidateBody(), C5LifecycleFixtures.matrixHash());
        ConsequenceReview review = C5LifecycleFixtures.review(current, candidate);
        ConsequenceApprovalRecord approval = C5LifecycleFixtures.approve(review, "sec-reviewer-01");

        ActiveTenantDirectory dir = C5LifecycleFixtures.directory();
        dir.activate(C5LifecycleFixtures.TENANT, current.bundleId());

        PolicyBundleRepository bundles = C5LifecycleFixtures.bundleRepo();
        ApprovalRepository approvals = C5LifecycleFixtures.approvalRepo();
        PolicyPromotionService svc = C5LifecycleFixtures.promotionService(
                dir, C5LifecycleFixtures.promotionRepo(), bundles, approvals,
                C5LifecycleFixtures.passingProbe(), "commit-c5-headline");
        svc.promote(new PromotionRequest(candidate, review, approval, "promo-examiner", PromotionRecord.Kind.PROMOTION));

        // ── A request runs under the now-active candidate; its audit + decision are recorded. ──
        ApplicationAuditRepository auditRepo = C5LifecycleFixtures.auditRepo();
        CerbosDecisionRepository decisionRepo = C5LifecycleFixtures.decisionRepo();
        String callId = "cerbos-call-7f3a";
        auditRepo.save(new ApplicationAuditEntry(
                "txn-9001", C5LifecycleFixtures.TENANT, callId, candidate.bundleId(), Instant.parse("2026-07-17T10:00:00Z")));
        decisionRepo.save(new CerbosDecisionEntry(
                callId, C5LifecycleFixtures.TENANT, candidate.bundleId(), "ALLOW", "agent", "invoke", Instant.parse("2026-07-17T10:00:00Z")));

        ConsequenceReviewSigner signer = C5LifecycleFixtures.signer();
        ExaminerChainService examiner = new ExaminerChainService(
                auditRepo, decisionRepo, bundles, approvals, C5LifecycleFixtures.canon(), signer);

        // ── Reconstruct the chain — complete, joined end to end. ──
        ExaminerChain chain = examiner.reconstruct(callId);
        assertThat(chain.complete()).isTrue();
        assertThat(chain.transactionId()).isEqualTo("txn-9001");
        assertThat(chain.tenantId()).isEqualTo(C5LifecycleFixtures.TENANT);
        assertThat(chain.activePolicyVersion()).isEqualTo(candidate.bundleId());
        assertThat(chain.bundleId()).isEqualTo(candidate.bundleId());
        assertThat(chain.decision()).isEqualTo("ALLOW");
        assertThat(chain.gitCommit()).isEqualTo("commit-c5-headline");
        assertThat(chain.approverId()).isEqualTo("sec-reviewer-01");
        assertThat(chain.approvalSignatureValid()).isTrue();
        assertThat(chain.consequenceReviewHash()).isEqualTo(review.consequenceReviewHash());
        assertThat(chain.testMetadata().fixtureSetHash()).isEqualTo(C5LifecycleFixtures.matrixHash());

        // ── The examiner holds NO LLM collaborator of any kind — the chain needs no model. ──
        for (Field f : ExaminerChainService.class.getDeclaredFields()) {
            assertThat(PolicyAuthoringModelClient.class.isAssignableFrom(f.getType()))
                    .as("examiner field %s must not be an authoring model client", f.getName()).isFalse();
            assertThat(ConsequenceProseModelClient.class.isAssignableFrom(f.getType()))
                    .as("examiner field %s must not be a prose model client", f.getName()).isFalse();
        }

        // ── Broken joins are FAILURES, not warnings. ──
        // (a) unknown call id — no application audit entry.
        assertThatThrownBy(() -> examiner.reconstruct("no-such-call"))
                .isInstanceOf(AuditIntegrityException.class).hasMessageContaining("no application audit");

        // (b) version mismatch — audit ran under the bundle, decision log recorded a different version.
        auditRepo.save(new ApplicationAuditEntry("txn-2", C5LifecycleFixtures.TENANT, "call-mismatch",
                candidate.bundleId(), Instant.parse("2026-07-17T10:05:00Z")));
        decisionRepo.save(new CerbosDecisionEntry("call-mismatch", C5LifecycleFixtures.TENANT,
                "b_some_other_version", "ALLOW", "agent", "invoke", Instant.parse("2026-07-17T10:05:00Z")));
        assertThatThrownBy(() -> examiner.reconstruct("call-mismatch"))
                .isInstanceOf(AuditIntegrityException.class).hasMessageContaining("split across bundle versions");

        // (c) tenant mismatch — an audit entry can never join a decision from another tenant.
        auditRepo.save(new ApplicationAuditEntry("txn-tenant", C5LifecycleFixtures.TENANT, "call-tenant-mismatch",
                candidate.bundleId(), Instant.parse("2026-07-17T10:05:30Z")));
        decisionRepo.save(new CerbosDecisionEntry("call-tenant-mismatch", "other-tenant",
                candidate.bundleId(), "ALLOW", "agent", "invoke", Instant.parse("2026-07-17T10:05:30Z")));
        assertThatThrownBy(() -> examiner.reconstruct("call-tenant-mismatch"))
                .isInstanceOf(AuditIntegrityException.class).hasMessageContaining("tenant mismatch");

        // (d) missing bundle record — decision references a bundle that was never recorded.
        auditRepo.save(new ApplicationAuditEntry("txn-3", C5LifecycleFixtures.TENANT, "call-ghost",
                "b_ghost_bundle", Instant.parse("2026-07-17T10:06:00Z")));
        decisionRepo.save(new CerbosDecisionEntry("call-ghost", C5LifecycleFixtures.TENANT,
                "b_ghost_bundle", "DENY", "agent", "invoke", Instant.parse("2026-07-17T10:06:00Z")));
        assertThatThrownBy(() -> examiner.reconstruct("call-ghost"))
                .isInstanceOf(AuditIntegrityException.class).hasMessageContaining("no immutable bundle record");

        writeEvidence(chain, candidate, review, approval);
    }

    private void writeEvidence(ExaminerChain chain, PolicyBundle candidate, ConsequenceReview review,
                              ConsequenceApprovalRecord approval) throws Exception {
        Path repoRoot = Path.of(System.getProperty("user.dir")).getParent();
        Path dir = repoRoot.resolve("docs/implementation/evidence/studio/c5");
        if (!Files.isDirectory(dir.getParent())) {
            return; // evidence tree not present in this checkout — nothing to write
        }
        Files.createDirectories(dir);

        // Headline 1: the full reconstructed examiner chain joining decision-log → bundle → approver → tests.
        Map<String, Object> chainView = new LinkedHashMap<>();
        chainView.put("reconstructedWith", "immutable records only; LLM subsystem disabled (no model client on the examiner)");
        chainView.put("transactionId", chain.transactionId());
        chainView.put("tenantId", chain.tenantId());
        chainView.put("cerbosCallId", chain.cerbosCallId());
        chainView.put("activePolicyVersion", chain.activePolicyVersion());
        chainView.put("decision", chain.decision());
        chainView.put("resourceKind", chain.resourceKind());
        chainView.put("action", chain.action());
        Map<String, Object> bundleHop = new LinkedHashMap<>();
        bundleHop.put("bundleId", chain.bundleId());
        bundleHop.put("gitCommit", chain.gitCommit());
        Map<String, Object> testsHop = new LinkedHashMap<>();
        testsHop.put("fixtureSetHash", chain.testMetadata().fixtureSetHash());
        testsHop.put("testCount", chain.testMetadata().testCount());
        testsHop.put("oracle", chain.testMetadata().oracle());
        testsHop.put("pdpSourceId", chain.testMetadata().pdpSourceId());
        bundleHop.put("tests", testsHop);
        chainView.put("immutableBundleRecord", bundleHop);
        Map<String, Object> approverHop = new LinkedHashMap<>();
        approverHop.put("approverId", chain.approverId());
        approverHop.put("consequenceReviewHash", chain.consequenceReviewHash());
        approverHop.put("signatureValid", chain.approvalSignatureValid());
        chainView.put("approval", approverHop);
        chainView.put("complete", chain.complete());
        Files.writeString(dir.resolve("examiner-chain.json"),
                JSON.writerWithDefaultPrettyPrinter().writeValueAsString(chainView));

        // Headline 2: the canonical-hash fixture — reproducible bundleId over the sentinel-form bytes.
        Map<String, Object> hashFixture = new LinkedHashMap<>();
        hashFixture.put("bundleId", candidate.bundleId());
        hashFixture.put("idScheme", "b_ + sha256(canonicalContent)");
        hashFixture.put("versionSentinel", BundleCanonicalizer.BUNDLE_VERSION_SENTINEL);
        hashFixture.put("note", "every policy version in the hash input is the sentinel (no self-reference); "
                + "the concrete bundleId is stamped back only when rendered for staging/compile");
        hashFixture.put("tenantId", candidate.tenantId());
        hashFixture.put("manifestRefs", candidate.manifestRefs());
        hashFixture.put("canonicalContent", candidate.canonicalContent());
        hashFixture.put("recomputedBundleId", C5LifecycleFixtures.canon().bundleId(candidate.canonicalContent()));
        Files.writeString(dir.resolve("canonical-hash-fixture.json"),
                JSON.writerWithDefaultPrettyPrinter().writeValueAsString(hashFixture));
    }
}
