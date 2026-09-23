package com.openwolf.iam.auth;

import com.openwolf.iam.service.AgentExchangeAuthorityService;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;

/** Fail-closed decoder boundary for every token that may enter RFC 8693 exchange. */
public final class TokenExchangeSubjectAuthorityValidator implements OAuth2TokenValidator<Jwt> {
    private static final OAuth2Error INVALID = new OAuth2Error("invalid_token");
    private final CustomerTokenAuthorityValidator customers;
    private final AgentExchangeAuthorityService agents;

    public TokenExchangeSubjectAuthorityValidator(CustomerTokenAuthorityValidator customers,
                                                  AgentExchangeAuthorityService agents) {
        this.customers = customers;
        this.agents = agents;
    }

    @Override
    public OAuth2TokenValidatorResult validate(Jwt token) {
        if ("customer".equals(token.getClaimAsString("identity_kind"))
                && !token.getClaims().containsKey("act")) {
            return customers.validate(token);
        }
        try {
            agents.requireValidNonCustomerSubject(token);
            return OAuth2TokenValidatorResult.success();
        } catch (RuntimeException denied) {
            return OAuth2TokenValidatorResult.failure(INVALID);
        }
    }
}
