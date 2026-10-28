package com.openwolf.iam.auth;

import java.net.URI;
import java.util.Objects;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.*;
import org.springframework.security.oauth2.server.authorization.authentication.*;

/** Literal comparison, with only the port of an explicitly registered HTTP loopback URI ignored. */
public final class LoopbackRedirects {
    private LoopbackRedirects() {}
    public static boolean isLoopback(String value) {
        try {
            URI uri = URI.create(value);
            return "http".equals(uri.getScheme()) && uri.getRawUserInfo() == null && uri.getRawFragment() == null && uri.getPort() != 0 && uri.getPort() <= 65535
                    && uri.getHost() != null && java.util.Set.of("127.0.0.1", "[::1]", "localhost").contains(uri.getHost());
        } catch (RuntimeException invalid) { return false; }
    }
    public static boolean matches(String registered, String requested) {
        if (registered.equals(requested)) return true;
        if (!isLoopback(registered) || !isLoopback(requested)) return false;
        URI a = URI.create(registered), b = URI.create(requested);
        return a.getHost().equals(b.getHost()) && Objects.equals(a.getRawPath(), b.getRawPath())
                && Objects.equals(a.getRawQuery(), b.getRawQuery());
    }
    public static void validate(OAuth2AuthorizationCodeRequestAuthenticationContext context) {
        OAuth2AuthorizationCodeRequestAuthenticationToken request = context.getAuthentication();
        String redirect = request.getRedirectUri();
        if (redirect == null) {
            OAuth2AuthorizationCodeRequestAuthenticationValidator.DEFAULT_REDIRECT_URI_VALIDATOR.accept(context);
            return;
        }
        if (context.getRegisteredClient().getRedirectUris().stream().anyMatch(uri -> matches(uri, redirect))) return;
        // Untrusted redirect values must never survive into an error redirect.
        var safe = new OAuth2AuthorizationCodeRequestAuthenticationToken(request.getAuthorizationUri(), request.getClientId(),
                (Authentication) request.getPrincipal(), null, request.getState(), request.getScopes(), request.getAdditionalParameters());
        throw new OAuth2AuthorizationCodeRequestAuthenticationException(new OAuth2Error(OAuth2ErrorCodes.INVALID_REQUEST), safe);
    }
}
