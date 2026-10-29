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
import java.util.UUID;

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
    private static final String DIRECT_LOGOUT_NONCE = OidcEndSessionCleanupFilter.class.getName() + ".nonce";

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        return !END_SESSION_ENDPOINT.equals(request.getRequestURI());
    }

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain) throws ServletException, IOException {
        // A person can visit the advertised logout URL directly, without an RP's id_token_hint.
        // OIDC requires confirmation before ending that browser session. Do not treat arbitrary
        // client_id or redirect parameters as a direct visit; those belong to the OIDC provider.
        if (request.getParameterMap().isEmpty() && "GET".equals(request.getMethod())) {
            showDirectLogoutConfirmation(request, response);
            return;
        }
        if ("POST".equals(request.getMethod()) && request.getParameterMap().size() == 2
                && request.getParameterMap().containsKey("confirm_logout")
                && request.getParameterMap().containsKey("nonce")) {
            completeDirectLogout(request, response);
            return;
        }
        HttpSession session = request.getSession(false);
        clearSessionCookie(request, response);
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

    private static void showDirectLogoutConfirmation(HttpServletRequest request, HttpServletResponse response)
            throws IOException {
        HttpSession session = request.getSession(false);
        if (session == null) {
            clearSessionCookie(request, response);
            writePage(response, "Already signed out", "There is no active Axiom browser session to end.", null);
            return;
        }
        String nonce = UUID.randomUUID().toString();
        session.setAttribute(DIRECT_LOGOUT_NONCE, nonce);
        writePage(response, "Sign out of Axiom?", "This ends your Axiom browser sign-in.", nonce);
    }

    private static void completeDirectLogout(HttpServletRequest request, HttpServletResponse response)
            throws IOException {
        HttpSession session = request.getSession(false);
        String submitted = request.getParameter("nonce");
        String expected = session == null ? null : (String) session.getAttribute(DIRECT_LOGOUT_NONCE);
        if (!"yes".equals(request.getParameter("confirm_logout")) || expected == null
                || !expected.equals(submitted)) {
            response.sendError(HttpServletResponse.SC_FORBIDDEN);
            return;
        }
        session.invalidate();
        SecurityContextHolder.clearContext();
        clearSessionCookie(request, response);
        writePage(response, "Signed out", "Your Axiom browser session has ended.", null);
    }

    private static void clearSessionCookie(HttpServletRequest request, HttpServletResponse response) {
        Cookie cleared = new Cookie("JSESSIONID", "");
        cleared.setPath("/");
        cleared.setHttpOnly(true);
        cleared.setSecure(request.isSecure());
        cleared.setMaxAge(0);
        cleared.setAttribute("SameSite", "Lax");
        response.addCookie(cleared);
    }

    private static void writePage(HttpServletResponse response, String title, String message, String nonce)
            throws IOException {
        response.setContentType("text/html;charset=UTF-8");
        response.setHeader("Cache-Control", "no-store");
        response.setHeader("Content-Security-Policy",
                "default-src 'none'; style-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'");
        response.getWriter().write("<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">"
                + "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"
                + "<title>" + title + "</title><link rel=\"stylesheet\" href=\"/css/axiom-login.css\">"
                + "</head><body><main class=\"login-card\"><h1>" + title + "</h1><p>" + message + "</p>"
                + (nonce == null ? "" : "<form method=\"post\" action=\"/connect/logout\">"
                    + "<input type=\"hidden\" name=\"confirm_logout\" value=\"yes\">"
                    + "<input type=\"hidden\" name=\"nonce\" value=\"" + nonce + "\">"
                    + "<button type=\"submit\" class=\"btn-sign-in\">Sign out</button></form>")
                + "</main></body></html>");
    }
}
