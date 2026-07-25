package com.openwolf.iam.policystudio.api;

import com.openwolf.iam.policystudio.ConsequenceReview;
import com.openwolf.iam.policystudio.GroundedStudioReviewService;
import com.openwolf.iam.policystudio.lifecycle.PolicyBundle;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

import java.time.Instant;
import java.util.List;
import java.util.Optional;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * C4 consequence-diff endpoint. The truth is computed by {@link GroundedStudioReviewService} from real
 * PDP decisions over a manifest-derived fixture matrix; the service records the VERIFIED author + tenant
 * with the review so promotion can later enforce author≠approver. Tenant is the claim; a cross-tenant
 * re-fetch resolves as 404.
 *
 * <p><b>S2 trusted inputs.</b> Grounding — the two bundle snapshots, the sampled matrix, and the
 * vocabulary — is NEVER accepted from the caller: the route takes only the authored {@code canonicalYaml}
 * (+ a {@code resourceKind} selector), and grounding is derived server-side. A caller that smuggles
 * {@code current}/{@code candidate}/{@code matrix}/{@code vocabulary} into the body is ignored — those
 * fields no longer exist on the payload and never reach the derivation.
 */
@WebMvcTest(controllers = StudioReviewController.class)
@Import(StudioTestSecurityConfig.class)
class StudioReviewControllerTest {

    @Autowired MockMvc mvc;
    @MockitoBean GroundedStudioReviewService reviews;
    @MockitoBean StudioSessionStore store;

    private static final String CANONICAL_YAML = "apiVersion: api.cerbos.dev/v1\nresourcePolicy: {}\n";

    /** A clean request: only the authored candidate + the resource-kind selector. */
    private static final String BODY = """
            {
              "resourceKind":"agent",
              "canonicalYaml":"apiVersion: api.cerbos.dev/v1\\nresourcePolicy: {}\\n"
            }
            """;

    /**
     * A poisoned request: the caller ALSO smuggles the two snapshots, a bogus matrix, and a widened
     * vocabulary into the body. These fields no longer exist on the payload and must be ignored — only
     * the authored {@code canonicalYaml} + {@code resourceKind} may cross the boundary.
     */
    private static final String POISON_BODY = """
            {
              "resourceKind":"agent",
              "canonicalYaml":"apiVersion: api.cerbos.dev/v1\\nresourcePolicy: {}\\n",
              "current":{"bundleId":"POISON","policy":null,"ceiling":null,"canonicalContent":"x"},
              "candidate":{"bundleId":"POISON","policy":null,"ceiling":null,"canonicalContent":"y"},
              "matrix":{"cells":[],"fixtureSetHash":"POISON"},
              "vocabulary":{"resourceKind":"agent","actions":["exfiltrate"],"classifications":[],
                            "attributes":[],"roles":["attacker"],"approvedImports":[]}
            }
            """;

    private static ConsequenceReview review() {
        return new ConsequenceReview("meridian", "agent", "b0", "b1", "fs-1",
                List.of(), true, 3, "cd", "crh-1", null, null, Instant.now(), null);
    }

    private static PolicyBundle candidate() {
        return new PolicyBundle("b1", "meridian", List.of(), List.of(), null, "content");
    }

    @Test
    void computeReturnsReviewFromServerDerivedGrounding() throws Exception {
        when(reviews.assembleAndReview(eq("meridian"), eq("drafter-dan"), any(), any())).thenReturn(review());

        mvc.perform(post("/admin/studio/reviews")
                        .with(StudioMvc.principal("drafter-dan", "meridian", "policy_author"))
                        .contentType(MediaType.APPLICATION_JSON).content(BODY))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.consequenceReviewHash").value("crh-1"))
                .andExpect(jsonPath("$.overPermissionAlarm").value(true))
                .andExpect(jsonPath("$.principalsGainingAccess").value(3));

        // The VERIFIED tenant (claim) + author (sub) drive the review — grounding is derived server-side
        // from ONLY the authored candidate + resource kind, never a caller-supplied field.
        verify(reviews).assembleAndReview("meridian", "drafter-dan", "agent", CANONICAL_YAML);
    }

    /**
     * The lockdown proof: caller-supplied snapshots/matrix/vocabulary cannot poison the review. The
     * service is invoked with ONLY the trusted principal (tenant + author) and the authored candidate;
     * the poisoned {@code current}/{@code candidate}/{@code matrix}/{@code vocabulary} have nowhere to go.
     */
    @Test
    void callerSuppliedSnapshotsAndMatrixAreIgnored() throws Exception {
        when(reviews.assembleAndReview(eq("meridian"), eq("drafter-dan"), any(), any())).thenReturn(review());

        mvc.perform(post("/admin/studio/reviews")
                        .with(StudioMvc.principal("drafter-dan", "meridian", "policy_author"))
                        .contentType(MediaType.APPLICATION_JSON).content(POISON_BODY))
                .andExpect(status().isOk());

        // Exactly the trusted inputs reached the server-side derivation — no snapshot/matrix/vocabulary.
        verify(reviews).assembleAndReview("meridian", "drafter-dan", "agent", CANONICAL_YAML);
    }

    @Test
    void getFetchesCachedReview() throws Exception {
        when(store.getReview("meridian", "crh-1")).thenReturn(Optional.of(
                new StudioSessionStore.StoredReview("crh-1", "meridian", "drafter-dan", review(),
                        candidate(), false, Instant.now())));
        mvc.perform(get("/admin/studio/reviews/crh-1")
                        .with(StudioMvc.principal("bob", "meridian", "policy_approver")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.consequenceReviewHash").value("crh-1"));
    }

    @Test
    void approverListsSameTenantPendingReviewWithExactCandidate() throws Exception {
        when(store.pendingReviews("meridian")).thenReturn(List.of(
                new StudioSessionStore.StoredReview("crh-1", "meridian", "drafter-dan", review(),
                        candidate(), false, Instant.now())));

        mvc.perform(get("/admin/studio/reviews/pending")
                        .with(StudioMvc.principal("approver-bob", "meridian", "policy_approver")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[0].reviewId").value("crh-1"))
                .andExpect(jsonPath("$[0].authorId").value("drafter-dan"))
                .andExpect(jsonPath("$[0].candidate.bundleId").value("b1"));
        verify(store).pendingReviews("meridian");
    }

    @Test
    void authorCannotListApproverInbox() throws Exception {
        mvc.perform(get("/admin/studio/reviews/pending")
                        .with(StudioMvc.principal("drafter-dan", "meridian", "policy_author")))
                .andExpect(status().isForbidden());
    }

    @Test
    void getAnotherTenantsReviewIs404() throws Exception {
        when(store.getReview("meridian", "crh-1")).thenReturn(Optional.empty());
        mvc.perform(get("/admin/studio/reviews/crh-1")
                        .with(StudioMvc.principal("bob", "meridian", "policy_approver")))
                .andExpect(status().isNotFound());
    }

    @Test
    void nonStudioRoleIsDenied403() throws Exception {
        mvc.perform(post("/admin/studio/reviews")
                        .with(StudioMvc.principal("rm", "meridian", "chat_user"))
                        .contentType(MediaType.APPLICATION_JSON).content(BODY))
                .andExpect(status().isForbidden());
        verifyNoInteractions(reviews);
    }

    @Test
    void approverCannotCreateReview403() throws Exception {
        mvc.perform(post("/admin/studio/reviews")
                        .with(StudioMvc.principal("bob", "meridian", "policy_approver"))
                        .contentType(MediaType.APPLICATION_JSON).content(BODY))
                .andExpect(status().isForbidden());
        verifyNoInteractions(reviews);
    }
}
