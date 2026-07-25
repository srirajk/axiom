package com.openwolf.iam.auth;

import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Component;
import com.openwolf.iam.entity.TenantApplicationClient;
import com.openwolf.iam.service.TenantApplicationService;

import java.util.Collection;
import java.util.List;

/** Server-side proof that a subject-context request came from the bound machine client. */
@Component
public final class SubjectContextCaller {
    public TenantApplicationService.ClientAuthority requireAuthorized(String requestedTenantId) {
        return requireAuthorized(requestedTenantId, ApplicationScopes.SUBJECT_CONTEXT_READ);
    }

    /**
     * Binds a machine request to its persisted confidential client, tenant and application. The
     * request never selects an application: callers receive the authority from their client row.
     */
    public TenantApplicationService.ClientAuthority requireAuthorized(String requestedTenantId, String requiredScope) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null || !(authentication.getPrincipal() instanceof Jwt jwt)
                || !authentication.isAuthenticated()) {
            throw denied();
        }

        String clientId = jwt.getClaimAsString("client_id");
        String subject = jwt.getSubject();
        String tenantId = jwt.getClaimAsString("tenant_id");
        String authorizedParty = jwt.getClaimAsString("azp");
        List<String> audiences = jwt.getAudience();
        TenantApplicationService.ClientAuthority authority = applications.activeAuthority(clientId)
                .filter(candidate -> candidate.clientType() == TenantApplicationClient.Type.CONFIDENTIAL_SERVICE)
                .orElseThrow(SubjectContextCaller::denied);
        if (!clientId.equals(subject)
                || (authorizedParty != null && !clientId.equals(authorizedParty))
                || audiences.size() != 1
                || !authority.audience().equals(audiences.getFirst())
                || !scopes(jwt).contains(requiredScope)
                || !requestedTenantId.equals(tenantId)) {
            throw denied();
        }
        if (!authority.tenantId().equals(tenantId)) {
            throw denied();
        }
        return authority;
    }

    private final TenantApplicationService applications;

    public SubjectContextCaller(TenantApplicationService applications) {
        this.applications = applications;
    }

    private static List<String> scopes(Jwt jwt) {
        Object raw = jwt.getClaims().get("scope");
        if (raw instanceof Collection<?> values) {
            return values.stream().map(String::valueOf).toList();
        }
        if (raw instanceof String value) {
            return List.of(value.split(" "));
        }
        return List.of();
    }

    private static AccessDeniedException denied() {
        return new AccessDeniedException("subject-context caller is not authorized");
    }
}
