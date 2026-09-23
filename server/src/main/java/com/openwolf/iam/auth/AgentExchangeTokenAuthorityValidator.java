package com.openwolf.iam.auth;

import com.openwolf.iam.service.AgentExchangeAuthorityService;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;

/** Revalidates active Agent route or workforce authority for non-CIAM exchange tokens. */
public final class AgentExchangeTokenAuthorityValidator implements OAuth2TokenValidator<Jwt> {
    private static final OAuth2Error INVALID = new OAuth2Error("invalid_token");
    private final AgentExchangeAuthorityService authority;

    public AgentExchangeTokenAuthorityValidator(AgentExchangeAuthorityService authority) {
        this.authority = authority;
    }

    @Override
    public OAuth2TokenValidatorResult validate(Jwt token) {
        String profile = token.getClaimAsString("authority_profile");
        if (profile == null || "ciam_customer".equals(profile)) {
            return OAuth2TokenValidatorResult.success();
        }
        try {
            authority.requireValidIssuedToken(token);
            return OAuth2TokenValidatorResult.success();
        } catch (RuntimeException denied) {
            return OAuth2TokenValidatorResult.failure(INVALID);
        }
    }
}
