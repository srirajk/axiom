package com.openwolf.iam.auth;

import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;

/** Axiom resource APIs accept only Admin-targeted RFC 9068 access tokens. */
public final class AxiomApiJwtValidator implements OAuth2TokenValidator<Jwt> {
    public static final String AUDIENCE = "axiom-api";
    private static final OAuth2Error INVALID = new OAuth2Error("invalid_token");

    @Override
    public OAuth2TokenValidatorResult validate(Jwt token) {
        if (token.getAudience().size() != 1 || !token.getAudience().contains(AUDIENCE)
                || !"at+jwt".equals(token.getHeaders().get("typ"))) {
            return OAuth2TokenValidatorResult.failure(INVALID);
        }
        return OAuth2TokenValidatorResult.success();
    }
}
