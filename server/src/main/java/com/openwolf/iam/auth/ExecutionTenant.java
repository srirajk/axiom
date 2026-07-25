package com.openwolf.iam.auth;

import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Component;

/** Request-path tenant source: only a verified JWT tenant_id claim is admissible. */
@Component
public final class ExecutionTenant {
    public String require() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication != null && authentication.getPrincipal() instanceof Jwt jwt) {
            Object tenant = jwt.getClaims().get("tenant_id");
            if (tenant != null && !tenant.toString().isBlank()) return tenant.toString();
        }
        throw new AccessDeniedException("a verified tenant_id claim is required for this operation");
    }
}
