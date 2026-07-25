package com.openwolf.iam.policystudio.api;

import com.openwolf.iam.policystudio.GroundedStudioReviewService;
import com.openwolf.iam.policystudio.StudioGroundingProvider;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

import static org.mockito.Mockito.verifyNoInteractions;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@WebMvcTest(controllers = StudioGroundingController.class)
@Import(StudioTestSecurityConfig.class)
class StudioGroundingControllerTest {

    @Autowired MockMvc mvc;
    @MockitoBean StudioGroundingProvider grounding;
    @MockitoBean GroundedStudioReviewService reviews;

    private static final String BODY = """
            {"resourceKind":"agent","canonicalYaml":"apiVersion: api.cerbos.dev/v1\\nresourcePolicy: {}\\n"}
            """;

    @Test
    void approverCannotCreateAssembledReview() throws Exception {
        mvc.perform(post("/admin/studio/reviews/assembled")
                        .with(StudioMvc.principal("bob", "meridian", "policy_approver"))
                        .contentType(MediaType.APPLICATION_JSON).content(BODY))
                .andExpect(status().isForbidden());
        verifyNoInteractions(reviews);
    }

    @Test
    void approverCannotMaterializeCandidate() throws Exception {
        mvc.perform(post("/admin/studio/bundles/candidates")
                        .with(StudioMvc.principal("bob", "meridian", "policy_approver"))
                        .contentType(MediaType.APPLICATION_JSON).content(BODY))
                .andExpect(status().isForbidden());
        verifyNoInteractions(reviews);
    }
}
