package com.openwolf.iam.config;

import com.openwolf.iam.entity.Principal;
import com.openwolf.iam.repository.PrincipalRepository;
import com.openwolf.iam.service.ApplicationAccessService;
import com.openwolf.iam.service.TenantApplicationService;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;

import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class S256PkceEnforcementFilterTest {

    private final RegisteredClientRepository clients = mock(RegisteredClientRepository.class);
    private final TenantApplicationService applications = mock(TenantApplicationService.class);
    private final ApplicationAccessService applicationAccess = mock(ApplicationAccessService.class);
    private final PrincipalRepository principals = mock(PrincipalRepository.class);
    private final S256PkceEnforcementFilter filter = new S256PkceEnforcementFilter(
            provider(clients), provider(applications), provider(applicationAccess), provider(principals));

    @AfterEach
    void clearSecurityContext() {
        SecurityContextHolder.clearContext();
    }

    @Test
    void rejectsPlainPkceForPersistedPublicClient() throws Exception {
        MockHttpServletRequest request = authorizationRequest("sample-portal", "plain");
        when(clients.findByClientId("sample-portal")).thenReturn(publicClient("sample-portal"));
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, (ignoredRequest, ignoredResponse) -> {
            throw new AssertionError("plain PKCE must not reach the authorization server");
        });

        assertEquals(400, response.getStatus());
    }

    @Test
    void rejectsMissingPkceMethodForPersistedPublicClient() throws Exception {
        MockHttpServletRequest request = authorizationRequest("sample-portal", null);
        when(clients.findByClientId("sample-portal")).thenReturn(publicClient("sample-portal"));
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, (ignoredRequest, ignoredResponse) -> {
            throw new AssertionError("missing PKCE must not reach the authorization server");
        });

        assertEquals(400, response.getStatus());
    }

    @Test
    void permitsS256ForPersistedPublicClient() throws Exception {
        MockHttpServletRequest request = authorizationRequest("sample-portal", "S256");
        when(clients.findByClientId("sample-portal")).thenReturn(publicClient("sample-portal"));
        MockHttpServletResponse response = new MockHttpServletResponse();
        boolean[] proceeded = {false};

        filter.doFilter(request, response, (ignoredRequest, ignoredResponse) -> proceeded[0] = true);

        assertTrue(proceeded[0]);
    }

    @Test
    void rejectsS256WithoutCodeChallenge() throws Exception {
        MockHttpServletRequest request = authorizationRequest("sample-portal", "S256");
        when(clients.findByClientId("sample-portal")).thenReturn(publicClient("sample-portal"));
        request.removeParameter("code_challenge");
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, (ignoredRequest, ignoredResponse) -> {
            throw new AssertionError("a missing PKCE challenge must not reach the authorization server");
        });

        assertEquals(400, response.getStatus());
    }

    @Test
    void clearsInactiveBrowserSessionBeforeAuthorizeCanMintACode() throws Exception {
        MockHttpServletRequest request = authorizationRequest("axiom-admin", "S256");
        request.getSession(true);
        when(clients.findByClientId("axiom-admin")).thenReturn(publicClient("axiom-admin"));
        Principal inactive = new Principal("user-1", "tenant-a", "alice", "alice@example.test",
                "hash", false, "{}");
        when(principals.findById("user-1")).thenReturn(Optional.of(inactive));
        SecurityContextHolder.getContext().setAuthentication(
                new TestingAuthenticationToken("user-1", "", "ROLE_user"));
        MockHttpServletResponse response = new MockHttpServletResponse();
        boolean[] proceeded = {false};

        filter.doFilter(request, response, (ignoredRequest, ignoredResponse) -> proceeded[0] = true);

        assertTrue(proceeded[0]);
        assertTrue(request.getSession(false) == null);
        assertTrue(SecurityContextHolder.getContext().getAuthentication() == null);
    }

    @Test
    void rejectsRevokedApplicationMembershipBeforeAuthorizeCanMintACode() throws Exception {
        MockHttpServletRequest request = authorizationRequest("sample-portal", "S256");
        when(clients.findByClientId("sample-portal")).thenReturn(publicClient("sample-portal"));
        Principal active = new Principal("user-1", "tenant-a", "alice", "alice@example.test",
                "hash", true, "{}");
        when(principals.findById("user-1")).thenReturn(Optional.of(active));
        when(applications.activeAuthority("sample-portal")).thenReturn(Optional.of(
                new TenantApplicationService.ClientAuthority(
                        "tenant-a", "sample-api",
                        com.openwolf.iam.entity.TenantApplicationClient.Type.PUBLIC_BROWSER,
                        java.util.List.of("openid"))));
        when(applicationAccess.tokenClaims("sample-portal", "user-1"))
                .thenThrow(new IllegalStateException("membership revoked"));
        SecurityContextHolder.getContext().setAuthentication(
                new TestingAuthenticationToken("user-1", "", "ROLE_user"));
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, (ignoredRequest, ignoredResponse) -> {
            throw new AssertionError("revoked membership must not reach the authorization server");
        });

        assertEquals(403, response.getStatus());
    }

    @Test
    void permitsCurrentPrincipalAndApplicationMembership() throws Exception {
        MockHttpServletRequest request = authorizationRequest("sample-portal", "S256");
        when(clients.findByClientId("sample-portal")).thenReturn(publicClient("sample-portal"));
        Principal active = new Principal("user-1", "tenant-a", "alice", "alice@example.test",
                "hash", true, "{}");
        when(principals.findById("user-1")).thenReturn(Optional.of(active));
        when(applications.activeAuthority("sample-portal")).thenReturn(Optional.of(
                new TenantApplicationService.ClientAuthority(
                        "tenant-a", "sample-api",
                        com.openwolf.iam.entity.TenantApplicationClient.Type.PUBLIC_BROWSER,
                        java.util.List.of("openid"))));
        when(applicationAccess.tokenClaims("sample-portal", "user-1"))
                .thenReturn(Map.of("tenant_id", "tenant-a"));
        SecurityContextHolder.getContext().setAuthentication(
                new TestingAuthenticationToken("user-1", "", "ROLE_user"));
        MockHttpServletResponse response = new MockHttpServletResponse();
        boolean[] proceeded = {false};

        filter.doFilter(request, response, (ignoredRequest, ignoredResponse) -> proceeded[0] = true);

        assertTrue(proceeded[0]);
    }

    private static MockHttpServletRequest authorizationRequest(String clientId, String method) {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", S256PkceEnforcementFilter.AUTHORIZATION_ENDPOINT);
        request.setParameter("client_id", clientId);
        if (method != null) request.setParameter("code_challenge_method", method);
        if ("S256".equals(method)) request.setParameter("code_challenge", "challenge");
        return request;
    }

    private static RegisteredClient publicClient(String clientId) {
        return RegisteredClient.withId(clientId + "-id").clientId(clientId)
                .clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .redirectUri("https://sample.example/callback").scope("openid")
                .clientSettings(ClientSettings.builder().requireProofKey(true).build()).build();
    }

    private static <T> ObjectProvider<T> provider(T value) {
        @SuppressWarnings("unchecked") ObjectProvider<T> provider = mock(ObjectProvider.class);
        when(provider.getIfAvailable()).thenReturn(value);
        return provider;
    }
}
