package com.openwolf.iam.federation;

import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;

/** One non-disclosing authentication error for every federated runtime denial. */
public final class FederatedAuthenticationException extends OAuth2AuthenticationException {
    public FederatedAuthenticationException(Throwable cause) {
        super(new OAuth2Error("invalid_request", "federated identity is not available", null),
                "federated identity is not available", cause);
    }

    public FederatedAuthenticationException() {
        this(null);
    }
}
