package com.openwolf.iam.auth;

import com.openwolf.iam.entity.Principal;
import com.openwolf.iam.repository.PrincipalRepository;
import com.openwolf.iam.service.TenantApplicationService;
import org.springframework.stereotype.Component;

import java.util.LinkedHashSet;
import java.util.Set;

/** Resolves OAuth authorization state from server-owned human or service-client bindings only. */
@Component
public final class AuthorizationTenantResolver {
    private final PrincipalRepository principals;
    private final TenantApplicationService applications;

    public AuthorizationTenantResolver(PrincipalRepository principals, TenantApplicationService applications) {
        this.principals = principals;
        this.applications = applications;
    }

    public String resolve(String subject) {
        Set<String> candidates = new LinkedHashSet<>();
        principals.findById(subject).map(Principal::getTenantId).ifPresent(candidates::add);
        principals.findByUsername(subject).map(Principal::getTenantId).ifPresent(candidates::add);
        applications.activeAuthority(subject)
                .map(TenantApplicationService.ClientAuthority::tenantId)
                .ifPresent(candidates::add);
        if (candidates.size() != 1) {
            throw new IllegalStateException("authorization subject has no unique server-authoritative tenant binding");
        }
        return candidates.iterator().next();
    }
}
