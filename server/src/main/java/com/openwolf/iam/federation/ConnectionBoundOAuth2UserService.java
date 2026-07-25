package com.openwolf.iam.federation;

import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Component;

/** Userinfo client backed by the connection-bound OIDC transport. */
@Component
public final class ConnectionBoundOAuth2UserService implements OAuth2UserService<OAuth2UserRequest, OAuth2User> {
    private final DefaultOAuth2UserService delegate = new DefaultOAuth2UserService();

    public ConnectionBoundOAuth2UserService(ConnectionBoundOidcTransport transport) {
        delegate.setRestOperations(transport.restOperations());
    }

    @Override
    public OAuth2User loadUser(OAuth2UserRequest request) {
        try {
            return delegate.loadUser(request);
        } catch (FederatedAuthenticationException ex) {
            throw ex;
        } catch (RuntimeException ex) {
            throw new FederatedAuthenticationException(ex);
        }
    }
}
