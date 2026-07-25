package com.openwolf.iam.controller;

import com.openwolf.iam.auth.SubjectContextCaller;
import com.openwolf.iam.auth.ApplicationScopes;
import com.openwolf.iam.dto.SubjectContextResponse;
import com.openwolf.iam.service.SubjectContextService;
import com.openwolf.iam.service.ApplicationDecisionService;
import com.openwolf.iam.scim.ScimCredentialService;
import com.openwolf.iam.entity.TenantApplicationClient;
import com.openwolf.iam.service.TenantApplicationService;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;

import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@WebMvcTest(controllers = PlatformAuthzController.class)
@Import(PlatformAuthzControllerTest.TestSecurity.class)
class PlatformAuthzControllerTest {
    @Autowired MockMvc mvc;
    @MockitoBean SubjectContextCaller caller;
    @MockitoBean SubjectContextService service;
    @MockitoBean ApplicationDecisionService decisions;
    @MockitoBean ScimCredentialService scimCredentialService;

    @Test
    void returnsOnlyTheServiceDerivedContext() throws Exception {
        SubjectContextResponse response = new SubjectContextResponse("1.0", "request-1", "subject-1", "tenant-a", true,
                List.of("reader"), List.of("risk"), Map.of("classification", "internal"), "revision", java.time.Instant.now());
        when(caller.requireAuthorized("tenant-a")).thenReturn(new TenantApplicationService.ClientAuthority("tenant-a",
                "sample-api", TenantApplicationClient.Type.CONFIDENTIAL_SERVICE, List.of(ApplicationScopes.SUBJECT_CONTEXT_READ)));
        when(service.resolveForApplication(org.mockito.ArgumentMatchers.eq("request-1"), org.mockito.ArgumentMatchers.eq("subject-1"), org.mockito.ArgumentMatchers.eq("tenant-a"),
                org.mockito.ArgumentMatchers.any())).thenReturn(Optional.of(response));

        mvc.perform(post("/api/v1/platform-authz/subject-context")
                        .with(jwt().authorities(new SimpleGrantedAuthority(
                                "SCOPE_" + ApplicationScopes.SUBJECT_CONTEXT_READ)))
                        .contentType("application/vnd.axiom.platform-authz.v1+json")
                        .content("{\"contract_version\":\"1.0\",\"request_id\":\"request-1\",\"subject_id\":\"subject-1\",\"tenant_id\":\"tenant-a\",\"authentication_context\":{\"issuer\":\"https://issuer.example\",\"authenticated_at\":\"2026-07-25T00:00:00Z\",\"token_fingerprint\":\"sha256:test\"}}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.subject_id").value("subject-1"))
                .andExpect(jsonPath("$.tenant_id").value("tenant-a"))
                .andExpect(jsonPath("$.roles[0]").value("reader"))
                .andExpect(jsonPath("$.attributes.classification").value("internal"));
    }

    @Test
    void missingDedicatedScopeIsRejectedBeforeTheServiceRuns() throws Exception {
        mvc.perform(post("/api/v1/platform-authz/subject-context")
                        .with(jwt())
                        .contentType("application/vnd.axiom.platform-authz.v1+json")
                        .content("{\"contract_version\":\"1.0\",\"request_id\":\"request-1\",\"subject_id\":\"subject-1\",\"tenant_id\":\"tenant-a\",\"authentication_context\":{\"issuer\":\"https://issuer.example\",\"authenticated_at\":\"2026-07-25T00:00:00Z\",\"token_fingerprint\":\"sha256:test\"}}"))
                .andExpect(status().isForbidden());
        verifyNoInteractions(caller, service);
    }

    @TestConfiguration
    @EnableMethodSecurity
    static class TestSecurity {
        @Bean
        SecurityFilterChain testFilterChain(HttpSecurity http) throws Exception {
            return http.csrf(csrf -> csrf.disable())
                    .authorizeHttpRequests(auth -> auth.anyRequest().permitAll())
                    .build();
        }
    }
}
