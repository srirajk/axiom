package com.openwolf.iam.authority;

import com.openwolf.iam.entity.TenantApplicationClient;
import com.openwolf.iam.service.TenantApplicationService;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;

/**
 * The Phase 3 workload API accepts only a confidential client's own client-credentials token: no delegated or human
 * token, the client itself as subject, its own single audience, and an active client in the token's tenant now.
 */
public final class WorkloadClientTokenValidator implements OAuth2TokenValidator<Jwt> {
    private static final OAuth2Error INVALID = new OAuth2Error("invalid_token");
    private final TenantApplicationService applications;

    public WorkloadClientTokenValidator(TenantApplicationService applications) {
        this.applications = applications;
    }

    @Override
    public OAuth2TokenValidatorResult validate(Jwt token) {
        String clientId = token.getClaimAsString("client_id");
        String tenantId = token.getClaimAsString("tenant_id");
        if (!"workload".equals(token.getClaimAsString("identity_kind")) || token.getClaims().containsKey("act")
                || token.getClaims().containsKey("token_use") || clientId == null || tenantId == null
                || !clientId.equals(token.getSubject()) || token.getAudience() == null || token.getAudience().size() != 1) {
            return OAuth2TokenValidatorResult.failure(INVALID);
        }
        boolean current = applications.activeAuthority(clientId)
                .filter(a -> a.clientType() == TenantApplicationClient.Type.CONFIDENTIAL_SERVICE)
                .filter(a -> a.tenantId().equals(tenantId))
                .filter(a -> a.audience().equals(token.getAudience().getFirst()))
                .isPresent();
        return current ? OAuth2TokenValidatorResult.success() : OAuth2TokenValidatorResult.failure(INVALID);
    }
}
