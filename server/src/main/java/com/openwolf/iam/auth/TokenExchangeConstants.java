package com.openwolf.iam.auth;

import org.springframework.security.oauth2.core.AuthorizationGrantType;

/** RFC 8693 protocol constants and Axiom's bounded on-behalf-of profile. */
public final class TokenExchangeConstants {
    public static final String GRANT_TYPE_VALUE = "urn:ietf:params:oauth:grant-type:token-exchange";
    public static final AuthorizationGrantType GRANT_TYPE = new AuthorizationGrantType(GRANT_TYPE_VALUE);
    public static final String ACCESS_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:access_token";
    public static final String SUBJECT_AUDIENCE = "axiom-token-exchange";

    public static final String SUBJECT_TOKEN = "subject_token";
    public static final String SUBJECT_TOKEN_TYPE = "subject_token_type";
    public static final String ACTOR_TOKEN = "actor_token";
    public static final String REQUESTED_TOKEN_TYPE = "requested_token_type";
    public static final String AUDIENCE = "audience";
    public static final String RESOURCE = "resource";
    public static final String PURPOSE = "purpose";
    public static final String DELEGATION_ID = "delegation_id";

    public static final String CONTEXT_SUBJECT = TokenExchangeConstants.class.getName() + ".subject";
    public static final String CONTEXT_AUDIENCE = TokenExchangeConstants.class.getName() + ".audience";
    public static final String CONTEXT_PURPOSE = TokenExchangeConstants.class.getName() + ".purpose";
    public static final String CONTEXT_DELEGATION_ID = TokenExchangeConstants.class.getName() + ".delegation_id";
    public static final String CONTEXT_WORKLOAD_ID = TokenExchangeConstants.class.getName() + ".workload_id";
    public static final String CONTEXT_WORKLOAD_REF = TokenExchangeConstants.class.getName() + ".workload_ref";
    public static final String CONTEXT_ACTOR_CLIENT_ID = TokenExchangeConstants.class.getName() + ".actor_client_id";
    public static final String CONTEXT_AUTHORITY_PROFILE = TokenExchangeConstants.class.getName() + ".authority_profile";
    public static final String CONTEXT_AUTHORITY_ID = TokenExchangeConstants.class.getName() + ".authority_id";
    public static final String CONTEXT_TOKEN_USE = TokenExchangeConstants.class.getName() + ".token_use";
    public static final String CONTEXT_IDENTITY_KIND = TokenExchangeConstants.class.getName() + ".identity_kind";

    private TokenExchangeConstants() {}
}
