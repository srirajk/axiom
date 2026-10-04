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
    private final com.openwolf.iam.repository.CustomerIdentityRepository customers;

    public AuthorizationTenantResolver(PrincipalRepository principals, TenantApplicationService applications) {
        this(principals, applications, null);
    }

    @org.springframework.beans.factory.annotation.Autowired
    public AuthorizationTenantResolver(PrincipalRepository principals, TenantApplicationService applications,
                                       com.openwolf.iam.repository.CustomerIdentityRepository customers) {
        this.principals = principals;
        this.applications = applications;
        this.customers = customers;
    }

    public String resolve(String subject) {
        Set<String> candidates = new LinkedHashSet<>();
        principals.findById(subject).filter(Principal::isActive).map(Principal::getTenantId).ifPresent(candidates::add);
        principals.findByUsername(subject).filter(Principal::isActive).map(Principal::getTenantId).ifPresent(candidates::add);
        // A customer browser login (CIAM): the customer's own tenant. Customer ids are UUIDs; an ambiguous match with a
        // workforce principal id is refused below like any other ambiguity.
        if (customers != null) {
            try {
                customers.findById(java.util.UUID.fromString(subject))
                        .filter(customer -> customer.getStatus() == com.openwolf.iam.entity.CustomerIdentity.Status.ACTIVE)
                        .map(com.openwolf.iam.entity.CustomerIdentity::getTenantId).ifPresent(candidates::add);
            } catch (IllegalArgumentException notACustomerId) {
                // not a customer id
            }
        }
        applications.activeAuthority(subject)
                .map(TenantApplicationService.ClientAuthority::tenantId)
                .ifPresent(candidates::add);
        if (candidates.size() != 1) {
            throw new IllegalStateException("authorization subject has no unique server-authoritative tenant binding");
        }
        return candidates.iterator().next();
    }
}
