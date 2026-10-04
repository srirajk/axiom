package com.openwolf.iam.auth;

import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenContext;

import java.util.Set;

/**
 * Refresh-token policy: a refresh token is issued only when the {@code offline_access} scope (OIDC Core section 11) was
 * requested and granted for the originating authorization, and only to clients registered for the refresh grant.
 */
public final class OfflineAccess {
    public static final String SCOPE = "offline_access";

    private OfflineAccess() {}

    public static boolean granted(OAuth2TokenContext context) {
        OAuth2Authorization authorization = context.getAuthorization();
        Set<String> scopes = authorization != null && authorization.getAuthorizedScopes() != null
                && !authorization.getAuthorizedScopes().isEmpty()
                ? authorization.getAuthorizedScopes() : context.getAuthorizedScopes();
        return scopes != null && scopes.contains(SCOPE);
    }
}
