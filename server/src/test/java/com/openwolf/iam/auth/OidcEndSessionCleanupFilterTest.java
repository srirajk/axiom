package com.openwolf.iam.auth;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpSession;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.assertFalse;

class OidcEndSessionCleanupFilterTest {
    private final OidcEndSessionCleanupFilter filter = new OidcEndSessionCleanupFilter();

    @AfterEach
    void clearSecurityContext() {
        SecurityContextHolder.clearContext();
    }

    @Test
    void leavesSessionAvailableToOidcProviderThenInvalidatesItAndClearsCookie() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest(
                "GET", OidcEndSessionCleanupFilter.END_SESSION_ENDPOINT);
        request.addParameter("id_token_hint", "valid-hint-handled-by-oidc-provider");
        request.getSession(true);
        MockHttpServletResponse response = new MockHttpServletResponse();
        SecurityContextHolder.getContext().setAuthentication(
                new TestingAuthenticationToken("user-1", "", "ROLE_user"));
        boolean[] providerRan = {false};

        filter.doFilter(request, response, (ignoredRequest, ignoredResponse) -> {
            assertNotNull(request.getSession(false));
            providerRan[0] = true;
        });

        assertTrue(providerRan[0]);
        assertNull(request.getSession(false));
        assertNull(SecurityContextHolder.getContext().getAuthentication());
        Cookie cleared = response.getCookie("JSESSIONID");
        assertNotNull(cleared);
        assertEquals(0, cleared.getMaxAge());
        assertEquals("/", cleared.getPath());
        assertTrue(cleared.isHttpOnly());
    }

    @Test
    void directVisitAsksBeforeEndingBrowserSession() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/connect/logout");
        HttpSession session = request.getSession(true);
        MockHttpServletResponse response = new MockHttpServletResponse();
        boolean[] reachedOidcProvider = {false};

        filter.doFilter(request, response, (ignoredRequest, ignoredResponse) -> reachedOidcProvider[0] = true);

        assertFalse(reachedOidcProvider[0]);
        assertEquals(200, response.getStatus());
        assertTrue(response.getContentAsString().contains("Sign out of Axiom?"));
        assertTrue(response.getContentAsString().contains("name=\"nonce\""));
        assertEquals("no-store", response.getHeader("Cache-Control"));
        assertNull(response.getCookie("JSESSIONID"));
        assertNotNull(request.getSession(false));
        assertEquals(session, request.getSession(false));
    }

    @Test
    void confirmedDirectLogoutEndsOnlyTheBrowserSession() throws Exception {
        MockHttpServletRequest get = new MockHttpServletRequest("GET", "/connect/logout");
        HttpSession session = get.getSession(true);
        filter.doFilter(get, new MockHttpServletResponse(), (ignoredRequest, ignoredResponse) -> {});
        String nonce = (String) session.getAttribute(OidcEndSessionCleanupFilter.class.getName() + ".nonce");

        MockHttpServletRequest post = new MockHttpServletRequest("POST", "/connect/logout");
        post.setSession((org.springframework.mock.web.MockHttpSession) session);
        post.setSecure(true);
        post.addParameter("confirm_logout", "yes");
        post.addParameter("nonce", nonce);
        MockHttpServletResponse response = new MockHttpServletResponse();
        filter.doFilter(post, response, (ignoredRequest, ignoredResponse) -> {});

        assertEquals(200, response.getStatus());
        assertTrue(response.getContentAsString().contains("Your Axiom browser session has ended"));
        assertNull(post.getSession(false));
        assertEquals(0, response.getCookie("JSESSIONID").getMaxAge());
        assertTrue(response.getCookie("JSESSIONID").getSecure());
    }

    @Test
    void forgedConfirmationCannotEndBrowserSessionOrRedirect() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/connect/logout");
        request.getSession(true);
        request.addParameter("confirm_logout", "yes");
        request.addParameter("nonce", "made-up");
        MockHttpServletResponse response = new MockHttpServletResponse();
        filter.doFilter(request, response, (ignoredRequest, ignoredResponse) -> {});

        assertEquals(403, response.getStatus());
        assertNotNull(request.getSession(false));
        assertNull(response.getCookie("JSESSIONID"));
        assertNull(response.getRedirectedUrl());
    }

    @Test
    void directVisitWithoutSessionShowsSafeResult() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/connect/logout");
        MockHttpServletResponse response = new MockHttpServletResponse();
        filter.doFilter(request, response, (ignoredRequest, ignoredResponse) -> {});

        assertEquals(200, response.getStatus());
        assertTrue(response.getContentAsString().contains("Already signed out"));
        assertFalse(response.getContentAsString().contains("<form"));
        assertEquals(0, response.getCookie("JSESSIONID").getMaxAge());
    }
}
