package com.openwolf.iam.auth;

import jakarta.servlet.http.Cookie;
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
}
