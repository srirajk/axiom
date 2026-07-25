package com.openwolf.iam.policystudio.api;

import com.openwolf.iam.policystudio.lifecycle.ExaminerChain;
import com.openwolf.iam.policystudio.lifecycle.ExaminerChainService;
import com.openwolf.iam.policystudio.lifecycle.PolicyBundleRecord;
import com.openwolf.iam.policystudio.lifecycle.PolicyBundleRepository;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.Instant;
import java.util.List;

/**
 * The C5 lifecycle READ surface for the Policy Studio SPA: the immutable bundle history and the
 * zero-LLM examiner chain. Thin over {@link PolicyBundleRepository} and {@link ExaminerChainService};
 * it computes nothing itself.
 *
 * <p><b>Tenant scope</b> comes from the principal's {@code tenant_id} claim (never a query field): the
 * bundle list is filtered to the caller's tenant and a bundle from another tenant resolves as 404. All
 * reads require a studio role (drafter or approver) — additionally behind the {@code /admin/**} gate.
 */
@RestController
@RequestMapping("/admin/studio")
@PreAuthorize("hasAnyRole('policy_author','policy_approver','platform_admin')")
public class StudioLifecycleController {

    private final PolicyBundleRepository bundles;
    private final ExaminerChainService examiner;

    public StudioLifecycleController(PolicyBundleRepository bundles, ExaminerChainService examiner) {
        this.bundles = bundles;
        this.examiner = examiner;
    }

    /** A projection of an immutable bundle record (omits the bulky canonical bytes for the list view). */
    public record BundleView(String bundleId, String tenantId, String gitCommit, String fixtureSetHash,
                             int testCount, String testOracle, String pdpSourceId, Instant createdAt) {
        static BundleView of(PolicyBundleRecord r) {
            return new BundleView(r.getBundleId(), r.getTenantId(), r.getGitCommit(), r.getFixtureSetHash(),
                    r.getTestCount(), r.getTestOracle(), r.getPdpSourceId(), r.getCreatedAt());
        }
    }

    /** {@code GET /admin/studio/bundles} — this tenant's immutable bundle history, newest first. */
    @GetMapping("/bundles")
    public ResponseEntity<List<BundleView>> listBundles(Authentication auth) {
        String tenant = StudioPrincipal.tenant(auth);
        List<BundleView> view = bundles.findByTenantIdOrderByCreatedAtDesc(tenant).stream()
                .map(BundleView::of)
                .toList();
        return ResponseEntity.ok(view);
    }

    /** {@code GET /admin/studio/bundles/{bundleId}} — one bundle (404 if absent or another tenant's). */
    @GetMapping("/bundles/{bundleId}")
    public ResponseEntity<BundleView> getBundle(@PathVariable String bundleId, Authentication auth) {
        String tenant = StudioPrincipal.tenant(auth);
        return bundles.findById(bundleId)
                .filter(r -> r.getTenantId().equals(tenant))
                .map(r -> ResponseEntity.ok(BundleView.of(r)))
                .orElseGet(() -> ResponseEntity.notFound().build());
    }

    /**
     * {@code GET /admin/studio/examiner/{cerbosCallId}} — reconstruct the full audit chain for a recorded
     * authorization decision from immutable records, with zero LLM. A broken join is a 422 (an
     * {@code AuditIntegrityException} → {@link IllegalStateException} mapping) — never a partial chain.
     */
    @GetMapping("/examiner/{cerbosCallId}")
    public ResponseEntity<ExaminerChain> examiner(@PathVariable String cerbosCallId, Authentication auth) {
        String tenant = StudioPrincipal.tenant(auth);
        ExaminerChain chain = examiner.reconstruct(cerbosCallId);
        StudioPrincipal.assertSameTenant(tenant, chain.tenantId());
        return ResponseEntity.ok(chain);
    }
}
