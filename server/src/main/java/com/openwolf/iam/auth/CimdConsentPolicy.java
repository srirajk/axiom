package com.openwolf.iam.auth;

import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationContext;
import java.util.Set;

/** Every CIMD authorization requires a fresh decision, including openid-only and previously approved requests. */
public final class CimdConsentPolicy {
    private CimdConsentPolicy() {}
    public static boolean required(OAuth2AuthorizationCodeRequestAuthenticationContext context) {
        var client = context.getRegisteredClient();
        if (client.getClientSettings().getSetting(CimdRegisteredClientRepository.CLIENT_ID) != null) return true;
        // Preserve Spring 1.5.8's ordinary static-client policy.
        if (!client.getClientSettings().isRequireAuthorizationConsent()) return false;
        Set<String> scopes = context.getAuthorizationRequest().getScopes();
        if (scopes.equals(Set.of("openid"))) return false;
        var remembered = context.getAuthorizationConsent();
        return remembered == null || !remembered.getScopes().containsAll(scopes);
    }
}
