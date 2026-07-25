package com.openwolf.iam.auth;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

/** Prevents a recovery bearer from becoming a general application or policy credential. */
public final class RecoveryScopeFilter extends OncePerRequestFilter {
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication != null && authentication.getPrincipal() instanceof Jwt jwt
                && Boolean.TRUE.equals(jwt.getClaims().get("recovery"))
                && !RECOVERY_PATHS.matches(request.getRequestURI())) {
            response.sendError(HttpServletResponse.SC_FORBIDDEN, "recovery scope does not permit this resource");
            return;
        }
        chain.doFilter(request, response);
    }

    private static final RecoveryPathMatcher RECOVERY_PATHS = new RecoveryPathMatcher();

    private static final class RecoveryPathMatcher {
        boolean matches(String path) {
            if (path.startsWith("/users") || path.startsWith("/roles") || path.startsWith("/teams")
                    || path.startsWith("/domains") || path.startsWith("/admin/audit")) return true;
            if (!path.startsWith("/admin/tenants/")) return false;
            if (path.contains("/identity-sources") || path.contains("/signing-keys")
                    || path.contains("/scim-sources") || path.contains("/identity-control-requests")
                    || path.contains("/sessions") || path.contains("/recovery-operators")) return true;
            return path.contains("/applications") && !path.contains("/access");
        }
    }
}
