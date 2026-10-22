package com.openwolf.iam.auth;

import com.openwolf.iam.service.TenantApplicationService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * Fail-closed RFC 8707 guard for Axiom's current one-audience authorization-code model.
 * A resource is accepted only if it is the tenant client's exact default audience and an absolute URI.
 * It never substitutes for OAuth client authentication or claims authorization.
 */
public final class AuthorizationCodeResourceGuardFilter extends OncePerRequestFilter {
    private final ObjectProvider<TenantApplicationService> applications;

    public AuthorizationCodeResourceGuardFilter(ObjectProvider<TenantApplicationService> applications) {
        this.applications = applications;
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        if (request.getParameterValues("resource") == null) return true;
        if ("/oauth/authorize".equals(request.getRequestURI())) return false;
        return !"/oauth/token".equals(request.getRequestURI())
                || !"POST".equalsIgnoreCase(request.getMethod())
                || !("authorization_code".equals(request.getParameter("grant_type"))
                        || "refresh_token".equals(request.getParameter("grant_type")));
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        String[] resources = request.getParameterValues("resource");
        String clientId = clientId(request);
        TenantApplicationService service = applications.getIfAvailable();
        if (resources == null || resources.length != 1 || !validResource(resources[0])
                || clientId == null || service == null || service.activeAuthority(clientId)
                        .filter(authority -> authority.clientType().interactive())
                        .filter(authority -> resources[0].equals(authority.audience())).isEmpty()) {
            response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            response.setContentType("application/json");
            response.getWriter().write("{\"error\":\"invalid_target\"}");
            return;
        }
        chain.doFilter(request, response);
    }

    private static boolean validResource(String value) {
        if (value == null || value.isBlank() || value.length() > 2048) return false;
        try {
            URI uri = new URI(value);
            return uri.isAbsolute() && uri.getFragment() == null;
        } catch (URISyntaxException invalid) {
            return false;
        }
    }

    private static String clientId(HttpServletRequest request) {
        String[] parameter = request.getParameterValues("client_id");
        if (parameter != null && parameter.length != 1) return null;
        String supplied = parameter == null ? null : parameter[0];
        if (!"/oauth/token".equals(request.getRequestURI())) return supplied;
        String header = request.getHeader("Authorization");
        if (header == null) return supplied;
        if (!header.startsWith("Basic ")) return null;
        try {
            String pair = new String(Base64.getDecoder().decode(header.substring(6)), StandardCharsets.UTF_8);
            int separator = pair.indexOf(':');
            if (separator < 1) return null;
            String basicId = URLDecoder.decode(pair.substring(0, separator), StandardCharsets.UTF_8);
            return supplied == null || supplied.equals(basicId) ? basicId : null;
        } catch (IllegalArgumentException invalid) {
            return null;
        }
    }
}
