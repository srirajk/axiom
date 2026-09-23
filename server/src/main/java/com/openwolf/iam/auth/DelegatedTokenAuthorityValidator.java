package com.openwolf.iam.auth;

import com.openwolf.iam.service.CiamDelegationAuthorityService;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;

import java.util.Collection;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

/** Revalidates persisted customer consent and workload authority on every delegated-token use. */
public final class DelegatedTokenAuthorityValidator implements OAuth2TokenValidator<Jwt> {
    private static final OAuth2Error INVALID = new OAuth2Error("invalid_token");
    private final CiamDelegationAuthorityService authority;

    public DelegatedTokenAuthorityValidator(CiamDelegationAuthorityService authority) {
        this.authority = authority;
    }

    @Override
    public OAuth2TokenValidatorResult validate(Jwt token) {
        if (!token.getClaims().containsKey("act") && !token.getClaims().containsKey("delegation_id")) {
            return OAuth2TokenValidatorResult.success();
        }
        String profile = token.getClaimAsString("authority_profile");
        if (profile != null && !"ciam_customer".equals(profile)) {
            return OAuth2TokenValidatorResult.success();
        }
        try {
            if (!"customer".equals(token.getClaimAsString("identity_kind"))) return failure();
            UUID customerId = UUID.fromString(token.getSubject());
            UUID delegationId = UUID.fromString(required(token, "delegation_id"));
            String tenantId = required(token, "tenant_id");
            String actorClientId = required(token, "client_id");
            String purpose = required(token, "purpose");
            List<String> audiences = token.getAudience();
            if (audiences == null || audiences.size() != 1) return failure();
            Map<?, ?> actor = token.getClaim("act");
            if (actor == null) return failure();
            String workloadRef = String.valueOf(actor.get("sub"));
            String workloadId = String.valueOf(actor.get("workload_id"));
            if (!actorClientId.equals(String.valueOf(actor.get("client_id")))) return failure();
            CiamDelegationAuthorityService.AuthorizedDelegation approved = authority.requireAuthorized(
                    tenantId, customerId, actorClientId, audiences.getFirst(), scopes(token));
            if (!delegationId.equals(approved.grantId()) || !purpose.equals(approved.purpose())
                    || !workloadRef.equals(approved.workloadRef())
                    || !workloadId.equals(approved.workloadId().toString())) return failure();
            return OAuth2TokenValidatorResult.success();
        } catch (RuntimeException rejected) {
            return failure();
        }
    }

    private static String required(Jwt token, String claim) {
        String value = token.getClaimAsString(claim);
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
        if (values.isEmpty()) throw new IllegalArgumentException("missing scopes");
        return values;
    }

    private static OAuth2TokenValidatorResult failure() {
        return OAuth2TokenValidatorResult.failure(INVALID);
    }
}
