package com.openwolf.iam.auth;

import java.util.Map;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.*;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.web.authentication.AuthenticationConverter;

/** Identifies an opted-in public refresh client; possession and client binding of the refresh token remain mandatory. */
public final class PublicRefreshClientAuthentication implements AuthenticationProvider {
    private final RegisteredClientRepository clients;
    public PublicRefreshClientAuthentication(RegisteredClientRepository clients) { this.clients = clients; }

    public static AuthenticationConverter converter() {
        return request -> {
            if (!"refresh_token".equals(request.getParameter("grant_type"))) return null;
            if (request.getHeader("Authorization") != null || request.getParameter("client_secret") != null
                    || request.getParameter("client_assertion") != null
                    || request.getParameter("client_assertion_type") != null) return null;
            String[] ids = request.getParameterValues("client_id");
            if (ids == null || ids.length != 1 || ids[0].isBlank()) {
                throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_CLIENT);
            }
            return new PublicRefreshToken(ids[0]);
        };
    }

    @Override public Authentication authenticate(Authentication authentication) {
        var client = clients.findByClientId(authentication.getName());
        if (client == null || !client.getClientAuthenticationMethods().equals(java.util.Set.of(ClientAuthenticationMethod.NONE))
                || !client.getAuthorizationGrantTypes().contains(AuthorizationGrantType.REFRESH_TOKEN)
                || !client.getScopes().contains(OfflineAccess.SCOPE) || client.getTokenSettings().isReuseRefreshTokens()) {
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_CLIENT);
        }
        return new OAuth2ClientAuthenticationToken(client, ClientAuthenticationMethod.NONE, null);
    }

    @Override public boolean supports(Class<?> type) { return type == PublicRefreshToken.class; }
    private static final class PublicRefreshToken extends OAuth2ClientAuthenticationToken {
        PublicRefreshToken(String id) { super(id, ClientAuthenticationMethod.NONE, null, Map.of()); }
    }
}
