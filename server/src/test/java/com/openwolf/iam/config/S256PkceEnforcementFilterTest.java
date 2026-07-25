package com.openwolf.iam.config;

import com.openwolf.iam.service.TenantApplicationService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class S256PkceEnforcementFilterTest {

    private final RegisteredClientRepository clients = mock(RegisteredClientRepository.class);
    private final TenantApplicationService applications = mock(TenantApplicationService.class);
    private final S256PkceEnforcementFilter filter = new S256PkceEnforcementFilter(provider(clients), provider(applications));

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
