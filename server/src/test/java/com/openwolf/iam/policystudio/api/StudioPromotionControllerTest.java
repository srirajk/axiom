package com.openwolf.iam.policystudio.api;

import com.openwolf.iam.policystudio.ApprovalDecision;
import com.openwolf.iam.policystudio.ConsequenceApprovalRecord;
import com.openwolf.iam.policystudio.ConsequenceApprovalService;
import com.openwolf.iam.policystudio.ConsequenceReview;
import com.openwolf.iam.policystudio.lifecycle.PolicyPromotionService;
import com.openwolf.iam.policystudio.lifecycle.PolicyBundle;
import com.openwolf.iam.policystudio.lifecycle.PromotionReceipt;
import com.openwolf.iam.policystudio.lifecycle.PromotionRecord;
import com.openwolf.iam.policystudio.lifecycle.PromotionRequest;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.Set;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;
import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * The C5 approve+promote gate — the marquee AUTHZ surface. Proves the endpoint (a) is shaped like the
 * real {@link PromotionReceipt}, (b) denies a non-approver 403, (c) enforces author≠approver 409 against
 * the VERIFIED author recorded server-side (never a body field), regardless of role, (d) fails closed 403
 * when the referenced review is not in this tenant's store, and (e) routes rollbacks to
 * {@link PolicyPromotionService#rollback}.
 */
@WebMvcTest(controllers = StudioPromotionController.class)
@Import(StudioTestSecurityConfig.class)
class StudioPromotionControllerTest {

    @Autowired MockMvc mvc;
    @MockitoBean ConsequenceApprovalService approvals;
    @MockitoBean PolicyPromotionService promotion;
    @MockitoBean StudioSessionStore store;

    private static String body(String candidateTenant) {
        return """
                {
                  "reviewId":"rev-1",
                  "candidate": {"bundleId":"b1","tenantId":"%s","files":[],"manifestRefs":[]},
                  "idempotencyKey":"idem-1"
                }
                """.formatted(candidateTenant);
    }

    private static ConsequenceReview review() {
        return new ConsequenceReview("meridian", "kind", "b0", "b1", "fs-1",
                List.of(), false, 0, "cd", "crh-1", null, null, Instant.now(), null);
    }

    private static PolicyBundle candidate() {
        return new PolicyBundle("b1", "meridian", List.of(), List.of(), null, "content");
    }

    /** A stored review computed (verified) by {@code author}, tenant meridian. */
    private void storedReviewBy(String author) {
        when(store.getReview(eq("meridian"), eq("rev-1")))
                .thenReturn(Optional.of(new StudioSessionStore.StoredReview(
                        "rev-1", "meridian", author, review(), candidate(), false, Instant.now())));
    }

    private ConsequenceApprovalRecord signed() {
        return new ConsequenceApprovalRecord("meridian", "b0", "b1", "fs-1", "crh-1", false,
                "approver-bob", Set.of("policy_approver"), ApprovalDecision.APPROVE, "sig", Instant.now());
    }

    @Test
    void approverPromotesAndGetsReceiptShape() throws Exception {
        storedReviewBy("alice");
        when(approvals.approve(any(), eq("approver-bob"), any(), eq(ApprovalDecision.APPROVE)))
                .thenReturn(signed());
        when(promotion.promote(any())).thenReturn(new PromotionReceipt(
                "promo-1", "meridian", "b0", "b1", 42L, PromotionRecord.Kind.PROMOTION, false));

        mvc.perform(post("/admin/studio/promotions")
                        .with(StudioMvc.principal("approver-bob", "meridian", "policy_approver"))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body("meridian")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.promotionId").value("promo-1"))
                .andExpect(jsonPath("$.toBundleId").value("b1"))
                .andExpect(jsonPath("$.directoryVersion").value(42))
                .andExpect(jsonPath("$.kind").value("PROMOTION"))
                .andExpect(jsonPath("$.idempotentReplay").value(false));
        verify(store).markReviewCompleted(any());
    }

    @Test
    void drafterRoleIsDenied403() throws Exception {
        mvc.perform(post("/admin/studio/promotions")
                        .with(StudioMvc.principal("someone", "meridian", "policy_author"))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body("meridian")))
                .andExpect(status().isForbidden());
        verifyNoInteractions(approvals, promotion);
    }

    @Test
    void verifiedAuthorCannotApproveOwnReview409() throws Exception {
        storedReviewBy("alice"); // the review was computed by the verified identity 'alice'
        mvc.perform(post("/admin/studio/promotions")
                        // ...and 'alice' is now the authenticated approver — self-approval is blocked.
                        .with(StudioMvc.principal("alice", "meridian", "policy_approver"))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body("meridian")))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.error").value("separation_of_duties"));
        verifyNoInteractions(approvals, promotion);
    }

    @Test
    void unknownOrCrossTenantReviewFailsClosed403() throws Exception {
        when(store.getReview(eq("meridian"), eq("rev-1"))).thenReturn(Optional.empty());
        mvc.perform(post("/admin/studio/promotions")
                        .with(StudioMvc.principal("approver-bob", "meridian", "policy_approver"))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body("meridian")))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.error").value("tenant_scope_violation"));
        verifyNoInteractions(approvals, promotion);
    }

    @Test
    void callerCandidateIsIgnoredAndExactStoredCandidateIsPromoted() throws Exception {
        storedReviewBy("alice");
        when(approvals.approve(any(), anyString(), any(), eq(ApprovalDecision.APPROVE))).thenReturn(signed());
        when(promotion.promote(any())).thenReturn(new PromotionReceipt(
                "promo-1", "meridian", "b0", "b1", 42L, PromotionRecord.Kind.PROMOTION, false));
        mvc.perform(post("/admin/studio/promotions")
                        .with(StudioMvc.principal("approver-bob", "meridian", "policy_approver"))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body("acme")))
                .andExpect(status().isOk());

        ArgumentCaptor<PromotionRequest> request = ArgumentCaptor.forClass(PromotionRequest.class);
        verify(promotion).promote(request.capture());
        assertThat(request.getValue().candidate()).isEqualTo(candidate());
    }

    @Test
    void rollbackRoutesToRollbackService() throws Exception {
        storedReviewBy("alice");
        when(approvals.approve(any(), anyString(), any(), eq(ApprovalDecision.APPROVE))).thenReturn(signed());
        when(promotion.rollback(any())).thenReturn(new PromotionReceipt(
                "promo-2", "meridian", "b1", "b0", 43L, PromotionRecord.Kind.ROLLBACK, false));

        mvc.perform(post("/admin/studio/rollbacks")
                        .with(StudioMvc.principal("approver-bob", "meridian", "policy_approver"))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body("meridian")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.kind").value("ROLLBACK"));
        verify(promotion, never()).promote(any());
        verify(store).markReviewCompleted(any());
    }

    @Test
    void failedPromotionLeavesReviewPending() throws Exception {
        storedReviewBy("alice");
        when(approvals.approve(any(), anyString(), any(), eq(ApprovalDecision.APPROVE))).thenReturn(signed());
        when(promotion.promote(any())).thenThrow(new IllegalStateException("probe failed"));

        mvc.perform(post("/admin/studio/promotions")
                        .with(StudioMvc.principal("approver-bob", "meridian", "policy_approver"))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body("meridian")))
                .andExpect(status().isUnprocessableEntity());
        verify(store, never()).markReviewCompleted(any());
    }

    @Test
    void completedSameKeyReplaysBeforeStaleApprovalCheck() throws Exception {
        storedReviewBy("alice");
        when(promotion.replayCompleted("idem-1", "meridian", "b0", "b1", "crh-1",
                "approver-bob", PromotionRecord.Kind.PROMOTION)).thenReturn(Optional.of(new PromotionReceipt(
                "promo-1", "meridian", "b0", "b1", 42L, PromotionRecord.Kind.PROMOTION, true)));

        mvc.perform(post("/admin/studio/promotions")
                        .with(StudioMvc.principal("approver-bob", "meridian", "policy_approver"))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body("acme")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.idempotentReplay").value(true));

        verifyNoInteractions(approvals);
        verify(promotion, never()).promote(any());
        verify(store).markReviewCompleted(any());
    }
}
