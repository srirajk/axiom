package com.openwolf.iam.auth;

import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;

/** Coarse validator for the service-only subject-context token path.
 * Exact registered-client tenant, audience and scope binding is enforced by {@link SubjectContextCaller}.
 */
public final class ApplicationSubjectContextJwtValidator implements OAuth2TokenValidator<Jwt> {
    private static final OAuth2Error INVALID = new OAuth2Error("invalid_token");

    @Override
    public OAuth2TokenValidatorResult validate(Jwt token) {
        if (token.getAudience().size() != 1
                || token.getAudience().getFirst() == null
                || token.getAudience().getFirst().isBlank()
                || !"at+jwt".equals(token.getHeaders().get("typ"))) {
            return OAuth2TokenValidatorResult.failure(INVALID);
        }
        return OAuth2TokenValidatorResult.success();
    }
}
