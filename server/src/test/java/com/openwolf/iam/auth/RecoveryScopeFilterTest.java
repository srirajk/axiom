package com.openwolf.iam.auth;

import jakarta.servlet.FilterChain;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.never;

class RecoveryScopeFilterTest {
    private final RecoveryScopeFilter filter = new RecoveryScopeFilter();

    @AfterEach
    void clear() { SecurityContextHolder.clearContext(); }

    @Test
    void blocksPolicyAndApplicationAccessForRecoveryToken() throws Exception {
        authenticateRecovery();
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/admin/studio/drafts");
        MockHttpServletResponse response = new MockHttpServletResponse();
        FilterChain chain = mock(FilterChain.class);

        filter.doFilter(request, response, chain);

        assertThat(response.getStatus()).isEqualTo(403);
        verify(chain, never()).doFilter(request, response);
    }

    @Test
    void permitsIdentityAdministrationPath() throws Exception {
        authenticateRecovery();
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/admin/tenants/tenant-a/recovery-operators");
        MockHttpServletResponse response = new MockHttpServletResponse();
        FilterChain chain = mock(FilterChain.class);

        filter.doFilter(request, response, chain);

        verify(chain).doFilter(request, response);
    }

    private static void authenticateRecovery() {
        SecurityContextHolder.getContext().setAuthentication(new org.springframework.security.authentication.UsernamePasswordAuthenticationToken(
                Jwt.withTokenValue("token").header("alg", "RS256").claim("recovery", true)
                        .claim("recovery_scope", "identity-admin").build(), null));
    }
}
