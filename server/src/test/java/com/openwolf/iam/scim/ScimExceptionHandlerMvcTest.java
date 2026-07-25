package com.openwolf.iam.scim;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.openwolf.iam.controller.ScimController;
import com.openwolf.iam.entity.ScimProvisioningSource;
import com.openwolf.iam.exception.GlobalExceptionHandler;
import com.openwolf.iam.service.ScimService;
import org.junit.jupiter.api.Test;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

class ScimExceptionHandlerMvcTest {
    @Test
    void preservesScimStatusAndEnvelopeAheadOfGlobalCatchAll() throws Exception {
        ScimService service = mock(ScimService.class);
        ScimProvisioningSource source = new ScimProvisioningSource("tenant-a", null, "Directory", "selector", "hash");
        doThrow(new ScimException(412, "If-Match does not match"))
                .when(service).replace(any(), any(), any(), any(), any(), any());
        MockMvc mvc = MockMvcBuilders.standaloneSetup(new ScimController(service))
                .setControllerAdvice(new ScimExceptionHandler(), new GlobalExceptionHandler()).build();

        var result = mvc.perform(put("/scim/v2/Users/user-1").requestAttr(ScimAuthenticationFilter.SOURCE_ATTRIBUTE, source)
                        .contentType("application/scim+json").content(new ObjectMapper().createObjectNode().put("userName", "user").toString()))
                .andExpect(status().isPreconditionFailed()).andReturn();

        assertThat(result.getResponse().getContentType()).startsWith("application/scim+json");
        assertThat(result.getResponse().getContentAsString()).contains(ScimError.ERROR_SCHEMA).contains("412");
    }

    @Test
    void preservesRepresentativeScim400404And501Envelopes() throws Exception {
        ScimController controller = new ScimController(mock(ScimService.class));
        MockMvc mvc = MockMvcBuilders.standaloneSetup(controller)
                .setControllerAdvice(new ScimExceptionHandler(), new GlobalExceptionHandler()).build();
        ScimProvisioningSource source = new ScimProvisioningSource("tenant-a", null, "Directory", "selector", "hash");

        assertScim(mvc.perform(delete("/scim/v2/Groups/group-1")
                .requestAttr(ScimAuthenticationFilter.SOURCE_ATTRIBUTE, source)), 400);
        assertScim(mvc.perform(org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get("/scim/v2/Nope")
                .requestAttr(ScimAuthenticationFilter.SOURCE_ATTRIBUTE, source)), 404);
        assertScim(mvc.perform(post("/scim/v2/Bulk").contentType("application/scim+json").content("{}")), 501);
    }

    private static void assertScim(org.springframework.test.web.servlet.ResultActions result, int status) throws Exception {
        var response = result.andExpect(status().is(status)).andReturn().getResponse();
        assertThat(response.getContentType()).startsWith("application/scim+json");
        assertThat(response.getContentAsString()).contains(ScimError.ERROR_SCHEMA).contains(Integer.toString(status));
    }
}
