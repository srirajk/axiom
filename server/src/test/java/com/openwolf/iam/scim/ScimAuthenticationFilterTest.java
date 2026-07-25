package com.openwolf.iam.scim;

import com.openwolf.iam.entity.ScimProvisioningSource;
import jakarta.servlet.FilterChain;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class ScimAuthenticationFilterTest {
    @Test
    void authenticatesOnlyTheSourceBoundBearerCredential() throws Exception {
        ScimCredentialService credentials = mock(ScimCredentialService.class);
        ScimAuthenticationFilter filter = new ScimAuthenticationFilter(credentials);
        ScimProvisioningSource source = new ScimProvisioningSource("tenant-a", null, "Directory", "selector", "hash");
        when(credentials.authenticate("selector.secret")).thenReturn(source);
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRequestURI("/scim/v2/Users");
        request.addHeader("Authorization", "Bearer selector.secret");
        MockHttpServletResponse response = new MockHttpServletResponse();
        FilterChain chain = mock(FilterChain.class);

        filter.doFilter(request, response, chain);

        assertThat(request.getAttribute(ScimAuthenticationFilter.SOURCE_ATTRIBUTE)).isSameAs(source);
        verify(chain).doFilter(request, response);
    }

    @org.junit.jupiter.params.ParameterizedTest
    @org.junit.jupiter.params.provider.ValueSource(strings = {"", "Basic abc", "Bearer", "Bearer selector"})
    void rejectsMissingWrongAndMalformedBearerHeadersAsScimErrors(String header) throws Exception {
        ScimCredentialService credentials = mock(ScimCredentialService.class);
        when(credentials.authenticate(org.mockito.ArgumentMatchers.anyString())).thenThrow(new ScimException(401, "bad"));
        ScimAuthenticationFilter filter = new ScimAuthenticationFilter(credentials);
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRequestURI("/scim/v2/Users");
        if (!header.isEmpty()) request.addHeader("Authorization", header);
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, mock(FilterChain.class));

        assertThat(response.getStatus()).isEqualTo(401);
        assertThat(response.getHeader("WWW-Authenticate")).isEqualTo("Bearer");
        assertThat(response.getContentAsString()).contains("urn:ietf:params:scim:api:messages:2.0:Error");
    }

    @org.junit.jupiter.api.Test
    void doesNotTouchNonScimRequests() throws Exception {
        ScimCredentialService credentials = mock(ScimCredentialService.class);
        ScimAuthenticationFilter filter = new ScimAuthenticationFilter(credentials);
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRequestURI("/auth/login");
        request.addHeader("Authorization", "Bearer would-not-be-read");
        MockHttpServletResponse response = new MockHttpServletResponse();
        FilterChain chain = mock(FilterChain.class);

        filter.doFilter(request, response, chain);

        verify(chain).doFilter(request, response);
        org.mockito.Mockito.verifyNoInteractions(credentials);
        assertThat(response.getStatus()).isEqualTo(200);
    }
}
