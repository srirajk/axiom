package com.openwolf.iam.policystudio.api;

import com.openwolf.iam.policystudio.ConsequenceReview;
import com.openwolf.iam.policystudio.GroundedStudioReviewService;
import com.openwolf.iam.policystudio.StudioGroundingProvider;
import com.openwolf.iam.policystudio.StudioGroundingSnapshot;
import com.openwolf.iam.policystudio.lifecycle.PolicyBundle;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * The grounded studio surface. Grounding — vocabulary, base ceiling, the current bundle snapshot, and the
 * sampled fixture matrix — is derived server-side from the tenant's manifest via {@link
 * StudioGroundingProvider} / {@link GroundedStudioReviewService}; the only caller inputs are the authored
 * {@code canonicalYaml} + a {@code resourceKind} selector. The tenant is always the principal's {@code
 * tenant_id} claim (never a body field).
 */
@RestController
@RequestMapping("/admin/studio")
@PreAuthorize("hasAnyRole('policy_author','policy_approver','platform_admin')")
public class StudioGroundingController {

    private final StudioGroundingProvider grounding;
    private final GroundedStudioReviewService reviews;

    public StudioGroundingController(StudioGroundingProvider grounding,
                                     GroundedStudioReviewService reviews) {
        this.grounding = grounding;
        this.reviews = reviews;
    }

    public record AssemblePayload(String resourceKind, String canonicalYaml) {}

    public record CandidateBundlePayload(String resourceKind, String canonicalYaml, String fixtureSetHash) {}

    @GetMapping("/vocabulary/{resourceKind}")
    public ResponseEntity<StudioGroundingSnapshot> vocabulary(@PathVariable String resourceKind, Authentication auth) {
        return ResponseEntity.ok(grounding.snapshot(StudioPrincipal.tenant(auth), resourceKind));
    }

    @PostMapping("/reviews/assembled")
    @PreAuthorize("hasRole('policy_author')")
    public ResponseEntity<ConsequenceReview> assembledReview(@RequestBody AssemblePayload payload, Authentication auth) {
        if (payload == null || payload.canonicalYaml() == null || payload.canonicalYaml().isBlank()) {
            throw new IllegalArgumentException("canonicalYaml is required");
        }
        String tenant = StudioPrincipal.tenant(auth);
        String author = StudioPrincipal.actor(auth);
        ConsequenceReview review = reviews.assembleAndReview(tenant, author, payload.resourceKind(), payload.canonicalYaml());
        return ResponseEntity.ok(review);
    }

    @PostMapping("/bundles/candidates")
    @PreAuthorize("hasRole('policy_author')")
    public ResponseEntity<PolicyBundle> candidateBundle(@RequestBody CandidateBundlePayload payload, Authentication auth) {
        if (payload == null || payload.canonicalYaml() == null || payload.canonicalYaml().isBlank()) {
            throw new IllegalArgumentException("canonicalYaml is required");
        }
        String tenant = StudioPrincipal.tenant(auth);
        PolicyBundle bundle = reviews.assembleCandidateBundle(
                tenant, payload.resourceKind(), payload.canonicalYaml(), payload.fixtureSetHash());
        return ResponseEntity.ok(bundle);
    }
}
