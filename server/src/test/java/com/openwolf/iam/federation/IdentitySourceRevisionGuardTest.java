package com.openwolf.iam.federation;

import com.openwolf.iam.entity.IdentitySource;
import com.openwolf.iam.repository.IdentitySourceRepository;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.client.endpoint.DefaultAuthorizationCodeTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2AuthorizationCodeGrantRequest;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.AuthorizationGrantType;

import java.time.Instant;
import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

class IdentitySourceRevisionGuardTest {
    @Test
    void disabledSourceIsRejectedBeforeTokenClientCanRun() {
        IdentitySource source = source();
        source.disable();
        IdentitySourceRepository sources = mock(IdentitySourceRepository.class);
        when(sources.findById(source.getId())).thenReturn(Optional.of(source));
        var guard = new IdentitySourceRevisionGuard(sources);

        assertThatThrownBy(() -> guard.requireActive(new IdentitySourceClientRegistrationRepository.RegistrationKey(
                source.getId(), source.getRevision())))
                .isInstanceOf(FederatedAuthenticationException.class)
                .hasMessage("federated identity is not available");
    }

    @Test
    void tokenClientDoesNotInvokeDelegateWhenSourceFenceIsStale() {
        IdentitySource source = source();
        IdentitySourceRepository sources = mock(IdentitySourceRepository.class);
        when(sources.findById(source.getId())).thenReturn(Optional.of(source));
        var guard = new IdentitySourceRevisionGuard(sources);
        DefaultAuthorizationCodeTokenResponseClient delegate = mock(DefaultAuthorizationCodeTokenResponseClient.class);
        var client = new FederatedAuthorizationCodeAccessTokenResponseClient(guard, delegate);
        ClientRegistration registration = ClientRegistration.withRegistrationId(
                        IdentitySourceClientRegistrationRepository.registrationId(source))
                .clientId("client").authorizationUri("https://idp.example.test/authorize")
                .tokenUri("https://idp.example.test/token")
                .redirectUri("http://localhost/callback")
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE).build();
        OAuth2AuthorizationCodeGrantRequest request = mock(OAuth2AuthorizationCodeGrantRequest.class);
        when(request.getClientRegistration()).thenReturn(registration);
        source.disable();

        org.assertj.core.api.Assertions.assertThatThrownBy(() -> client.getTokenResponse(request))
                .isInstanceOf(FederatedAuthenticationException.class);
        verifyNoInteractions(delegate);
    }

    private static IdentitySource source() {
        IdentitySource source = new IdentitySource("tenant-a", "IdP", "https://idp.example.test",
                "https://idp.example.test/discovery", "client", "ciphertext", List.of("openid"),
                List.of("RS256"), List.of("sub", "iss", "aud", "exp", "iat", "nonce"), List.of());
        source.applyValidatedMetadata("https://idp.example.test/authorize", "https://idp.example.test/token",
                "https://idp.example.test/userinfo", "https://idp.example.test/jwks", Instant.now());
        source.activate();
        return source;
    }
}
