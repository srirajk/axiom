package com.openwolf.iam.policystudio.api;

import com.openwolf.iam.policystudio.ConsequenceReview;
import com.openwolf.iam.policystudio.GroundedStudioReviewService;
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

import java.time.Instant;
import java.util.List;

/**
 * The C4 consequence-diff surface — the adoption unlock: a non-engineer approves business
 * <em>consequences</em>, not YAML. Thin over {@link GroundedStudioReviewService}, which runs real PDP
 * evaluations of a manifest-derived fixture matrix against the tenant's current bundle and the assembled
 * candidate and diffs the two answer sets. <b>No LLM touches the truth</b> — the returned {@link
 * ConsequenceReview} is computed entirely from PDP decisions.
 *
 * <p><b>Trusted inputs only (Axiom S2).</b> Grounding — the two bundle snapshots, the sampled fixture
 * matrix, and the vocabulary — is NEVER accepted from the caller: it is derived server-side from the
 * tenant's manifest. The only caller input is the authored candidate ({@code canonicalYaml}) plus a
 * {@code resourceKind} selector. The tenant is the principal's {@code tenant_id} claim, and the VERIFIED
 * author (subject) is recorded with the review so promotion can enforce author≠approver against a trusted
 * identity, never a caller-supplied field. Production truth comes only from the pinned Cerbos runtime,
 * which fails closed when unavailable — there is no local-evaluator fallback. Requires a studio role.
 */
@RestController
@RequestMapping("/admin/studio")
@PreAuthorize("hasAnyRole('policy_author','policy_approver','platform_admin')")
public class StudioReviewController {

    private final GroundedStudioReviewService reviews;
    private final StudioSessionStore store;

    public StudioReviewController(GroundedStudioReviewService reviews, StudioSessionStore store) {
        this.reviews = reviews;
        this.store = store;
    }

    /**
     * The consequence-diff request. Only the authored candidate ({@code canonicalYaml}) and the
     * {@code resourceKind} selector are accepted — grounding is derived server-side, never supplied here.
     */
    public record ReviewPayload(String resourceKind, String canonicalYaml) {}

    /** Server-recorded handoff: the exact reviewed candidate, never reconstructed by the approver. */
    public record ReviewHandoff(String reviewId, String authorId, ConsequenceReview review,
                                PolicyBundle candidate, Instant storedAt) {
        static ReviewHandoff from(StudioSessionStore.StoredReview stored) {
            return new ReviewHandoff(stored.reviewId(), stored.authorId(), stored.review(),
                    stored.candidate(), stored.storedAt());
        }
    }

    /** {@code POST /admin/studio/reviews} — compute the consequence review from real PDP decisions. */
    @PostMapping("/reviews")
    @PreAuthorize("hasRole('policy_author')")
    public ResponseEntity<ConsequenceReview> compute(@RequestBody ReviewPayload payload, Authentication auth) {
        if (payload == null || payload.canonicalYaml() == null || payload.canonicalYaml().isBlank()) {
            throw new IllegalArgumentException("canonicalYaml is required");
        }
        String author = StudioPrincipal.actor(auth);
        String tenant = StudioPrincipal.tenant(auth);
        ConsequenceReview review = reviews.assembleAndReview(tenant, author, payload.resourceKind(), payload.canonicalYaml());
        return ResponseEntity.ok(review);
    }

    /** {@code GET /admin/studio/reviews/pending} — same-tenant approver handoff inbox. */
    @GetMapping("/reviews/pending")
    @PreAuthorize("hasAnyRole('policy_approver','platform_admin')")
    public ResponseEntity<List<ReviewHandoff>> pending(Authentication auth) {
        String tenant = StudioPrincipal.tenant(auth);
        return ResponseEntity.ok(store.pendingReviews(tenant).stream().map(ReviewHandoff::from).toList());
    }

    /** {@code GET /admin/studio/reviews/{id}} — re-fetch a cached review (404 if absent / another tenant's). */
    @GetMapping("/reviews/{reviewId}")
    public ResponseEntity<ConsequenceReview> get(@PathVariable String reviewId, Authentication auth) {
        String tenant = StudioPrincipal.tenant(auth);
        return store.getReview(tenant, reviewId)
                .map(r -> ResponseEntity.ok(r.review()))
                .orElseGet(() -> ResponseEntity.notFound().build());
    }
}
