package com.openwolf.iam.federation;

import org.springframework.security.oauth2.client.endpoint.DefaultAuthorizationCodeTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2AccessTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2AuthorizationCodeGrantRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

/** Fences source status/revision before DefaultAuthorizationCodeTokenResponseClient can connect. */
@Component
public final class FederatedAuthorizationCodeAccessTokenResponseClient implements
        OAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest> {
    private final IdentitySourceRevisionGuard guard;
    private final DefaultAuthorizationCodeTokenResponseClient delegate;

    @Autowired
    public FederatedAuthorizationCodeAccessTokenResponseClient(
            IdentitySourceRevisionGuard guard, ConnectionBoundOidcTransport transport) {
        this(guard, configuredDelegate(transport));
    }

    FederatedAuthorizationCodeAccessTokenResponseClient(
            IdentitySourceRevisionGuard guard, DefaultAuthorizationCodeTokenResponseClient delegate) {
        this.guard = guard;
        this.delegate = delegate;
    }

    private static DefaultAuthorizationCodeTokenResponseClient configuredDelegate(
            ConnectionBoundOidcTransport transport) {
        DefaultAuthorizationCodeTokenResponseClient client = new DefaultAuthorizationCodeTokenResponseClient();
        client.setRestOperations(transport.restOperations());
        return client;
    }

    @Override
    public OAuth2AccessTokenResponse getTokenResponse(OAuth2AuthorizationCodeGrantRequest request) {
        try {
            var key = IdentitySourceClientRegistrationRepository.RegistrationKey.parse(
                    request.getClientRegistration().getRegistrationId());
            guard.requireActive(key);
            return delegate.getTokenResponse(request);
        } catch (FederatedAuthenticationException ex) {
            throw ex;
        } catch (RuntimeException ex) {
            throw new FederatedAuthenticationException(ex);
        }
    }
}
