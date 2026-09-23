package com.openwolf.iam.auth;

import com.openwolf.iam.entity.CustomerIdentity;
import com.openwolf.iam.entity.TenantApplicationClient;
import com.openwolf.iam.repository.CustomerIdentityRepository;
import com.openwolf.iam.service.TenantApplicationService;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;

import java.util.Collection;
import java.util.LinkedHashSet;
import java.util.Set;
import java.util.UUID;

/** Fail-closed authority check for short-lived customer subject tokens. */
public final class CustomerTokenAuthorityValidator implements OAuth2TokenValidator<Jwt> {
    private static final OAuth2Error INVALID = new OAuth2Error("invalid_token");
    private final CustomerIdentityRepository customers;
    private final TenantApplicationService applications;
    private final BusinessScopeRegistry businessScopes;
    private final boolean delegatedPassThrough;

    public CustomerTokenAuthorityValidator(CustomerIdentityRepository customers,
                                           TenantApplicationService applications,
                                           BusinessScopeRegistry businessScopes) {
        this(customers, applications, businessScopes, false);
    }

    public CustomerTokenAuthorityValidator(CustomerIdentityRepository customers,
                                           TenantApplicationService applications,
                                           BusinessScopeRegistry businessScopes,
                                           boolean delegatedPassThrough) {
        this.customers = customers;
        this.applications = applications;
        this.businessScopes = businessScopes;
        this.delegatedPassThrough = delegatedPassThrough;
    }

    @Override
    public OAuth2TokenValidatorResult validate(Jwt token) {
        if (token.getClaims().containsKey("act") || token.getClaims().containsKey("delegation_id")) {
            return delegatedPassThrough ? OAuth2TokenValidatorResult.success() : failure();
        }
        try {
            if (!"customer".equals(token.getClaimAsString("identity_kind"))
                    || token.getClaims().containsKey("roles")) return failure();
            if (token.getAudience() == null || token.getAudience().size() != 1
                    || !TokenExchangeConstants.SUBJECT_AUDIENCE.equals(token.getAudience().getFirst())) return failure();
            String tenantId = required(token, "tenant_id");
            String clientId = required(token, "client_id");
            UUID customerId = UUID.fromString(token.getSubject());
            Number tokenVersion = token.getClaim("token_version");
            if (tokenVersion == null) return failure();
            CustomerIdentity customer = customers.findByTenantIdAndId(tenantId, customerId).orElse(null);
            if (customer == null || customer.getStatus() != CustomerIdentity.Status.ACTIVE
                    || customer.getTokenVersion() != tokenVersion.longValue()) return failure();
            var client = applications.activeAuthority(clientId)
                    .filter(authority -> authority.clientType() == TenantApplicationClient.Type.PUBLIC_BROWSER)
                    .filter(authority -> authority.tenantId().equals(tenantId)).orElse(null);
            Set<String> scopes = scopes(token);
            if (client == null || scopes.isEmpty() || !client.scopes().containsAll(scopes)
                    || scopes.stream().anyMatch(scope -> !businessScopes.isApproved(scope))) return failure();
            return OAuth2TokenValidatorResult.success();
        } catch (RuntimeException invalid) {
            return failure();
        }
    }

    private static String required(Jwt token, String name) {
        String value = token.getClaimAsString(name);
        if (value == null || value.isBlank()) throw new IllegalArgumentException("missing claim");
        return value;
    }

    private static Set<String> scopes(Jwt token) {
        Object raw = token.getClaims().get("scope");
        Set<String> values = new LinkedHashSet<>();
        if (raw instanceof String text) {
            for (String scope : text.trim().split("\\s+")) if (!scope.isBlank()) values.add(scope);
        } else if (raw instanceof Collection<?> collection) {
            collection.forEach(scope -> values.add(String.valueOf(scope)));
        }
        return values;
    }

    private static OAuth2TokenValidatorResult failure() {
        return OAuth2TokenValidatorResult.failure(INVALID);
    }
}
