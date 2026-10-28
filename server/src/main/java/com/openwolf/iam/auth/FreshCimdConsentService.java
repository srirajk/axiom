package com.openwolf.iam.auth;

import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsent;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;

/** The authorization ceremony must evaluate this decision only. Customer consent management retains durable records. */
public final class FreshCimdConsentService implements OAuth2AuthorizationConsentService {
    private final OAuth2AuthorizationConsentService durable;
    public FreshCimdConsentService(OAuth2AuthorizationConsentService durable) { this.durable = durable; }
    @Override public OAuth2AuthorizationConsent findById(String clientId, String principalName) {
        var binding = CimdClientContext.current();
        return binding != null && binding.registeredClientId().equals(clientId) ? null : durable.findById(clientId, principalName);
    }
    @Override public void save(OAuth2AuthorizationConsent consent) { durable.save(consent); }
    @Override public void remove(OAuth2AuthorizationConsent consent) { durable.remove(consent); }
}
