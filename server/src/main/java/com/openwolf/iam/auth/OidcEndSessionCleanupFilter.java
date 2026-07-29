package com.openwolf.iam.auth;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

/**
 * Completes the browser side of RP-initiated logout.
 *
 * <p>Spring Authorization Server invalidates the authenticated server session at its OIDC
 * end-session endpoint, but it does not emit a deletion cookie for the servlet session. Leaving a
 * live-looking {@code JSESSIONID} in the browser creates exactly the stale-session ambiguity this
 * lifecycle closes. The request cookie remains available to the OIDC logout provider; cleanup runs
 * after it has processed the request, while the deletion header is prepared before a redirect can
 * commit the response.</p>
 */
@Component
public final class OidcEndSessionCleanupFilter extends OncePerRequestFilter {
    static final String END_SESSION_ENDPOINT = "/connect/logout";

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        return !END_SESSION_ENDPOINT.equals(request.getRequestURI());
    }

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain) throws ServletException, IOException {
        HttpSession session = request.getSession(false);
        Cookie cleared = new Cookie("JSESSIONID", "");
        cleared.setPath("/");
        cleared.setHttpOnly(true);
        cleared.setSecure(request.isSecure());
        cleared.setMaxAge(0);
        cleared.setAttribute("SameSite", "Lax");
        response.addCookie(cleared);
        try {
            filterChain.doFilter(request, response);
        } finally {
            if (session != null) {
                try {
                    session.invalidate();
                } catch (IllegalStateException alreadyInvalidated) {
                    // The OIDC logout provider normally owns server-side invalidation.
                }
            }
            SecurityContextHolder.clearContext();
        }
    }
}
