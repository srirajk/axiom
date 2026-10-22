package com.openwolf.iam.auth;

import com.openwolf.iam.entity.TenantApplicationClient;
import com.openwolf.iam.service.TenantApplicationService;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicBoolean;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.beans.factory.ObjectProvider;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class AuthorizationCodeResourceGuardFilterTest {
    private final TenantApplicationService applications = mock(TenantApplicationService.class);
    private final ObjectProvider<TenantApplicationService> provider = mock(ObjectProvider.class);
    private final AuthorizationCodeResourceGuardFilter filter = new AuthorizationCodeResourceGuardFilter(provider);
    private static final String RESOURCE = "https://api.example.test/payments";

    @BeforeEach
    void registered() {
        when(provider.getIfAvailable()).thenReturn(applications);
        when(applications.activeAuthority("browser")).thenReturn(Optional.of(
                new TenantApplicationService.ClientAuthority("tenant-a", RESOURCE,
                        TenantApplicationClient.Type.CONFIDENTIAL_WEB, List.of("read"), UUID.randomUUID())));
    }

    @Test
    void omittedResourcePreservesExistingCodeFlow() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/oauth/authorize");
        request.setParameter("client_id", "browser");
        assertAllowed(request);
    }

    @Test
    void exactRegisteredUriIsAllowedAtAuthorizeAndCodeRedemption() throws Exception {
        MockHttpServletRequest authorize = new MockHttpServletRequest("GET", "/oauth/authorize");
        authorize.setParameter("client_id", "browser");
        authorize.setParameter("resource", RESOURCE);
        assertAllowed(authorize);

        MockHttpServletRequest token = new MockHttpServletRequest("POST", "/oauth/token");
        token.setParameter("grant_type", "authorization_code");
        token.setParameter("resource", RESOURCE);
        token.addHeader("Authorization", "Basic " + Base64.getEncoder().encodeToString(
                "browser:secret".getBytes(StandardCharsets.UTF_8)));
        assertAllowed(token);
    }

    @Test
    void unknownDuplicateOrMalformedTargetsFailWithoutIssuing() throws Exception {
        for (String value : List.of("https://other.example.test", "relative-resource",
                "https://api.example.test/payments#fragment", "")) {
            MockHttpServletRequest request = new MockHttpServletRequest("GET", "/oauth/authorize");
            request.setParameter("client_id", "browser");
            request.setParameter("resource", value);
            assertDenied(request);
        }
        MockHttpServletRequest duplicate = new MockHttpServletRequest("GET", "/oauth/authorize");
        duplicate.setParameter("client_id", "browser");
        duplicate.setParameter("resource", RESOURCE, RESOURCE);
        assertDenied(duplicate);
    }

    @Test
    void tokenRequestCannotClaimAnotherClientOrTarget() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/oauth/token");
        request.setParameter("grant_type", "refresh_token");
        request.setParameter("resource", RESOURCE);
        request.setParameter("client_id", "other");
        request.addHeader("Authorization", "Basic " + Base64.getEncoder().encodeToString(
                "browser:secret".getBytes(StandardCharsets.UTF_8)));
        assertDenied(request);
    }

    private void assertAllowed(MockHttpServletRequest request) throws Exception {
        AtomicBoolean reachedOAuth = new AtomicBoolean();
        MockHttpServletResponse response = new MockHttpServletResponse();
        filter.doFilter(request, response, (ignoredRequest, ignoredResponse) -> reachedOAuth.set(true));
        assertThat(reachedOAuth).isTrue();
        assertThat(response.getStatus()).isEqualTo(200);
    }

    private void assertDenied(MockHttpServletRequest request) throws Exception {
        AtomicBoolean reachedOAuth = new AtomicBoolean();
        MockHttpServletResponse response = new MockHttpServletResponse();
        filter.doFilter(request, response, (ignoredRequest, ignoredResponse) -> reachedOAuth.set(true));
        assertThat(reachedOAuth).isFalse();
        assertThat(response.getStatus()).isEqualTo(400);
        assertThat(response.getContentAsString()).contains("invalid_target");
    }
}
