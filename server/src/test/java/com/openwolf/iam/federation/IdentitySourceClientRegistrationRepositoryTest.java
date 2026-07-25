package com.openwolf.iam.federation;

import com.openwolf.iam.entity.IdentitySource;
import com.openwolf.iam.repository.IdentitySourceRepository;
import com.openwolf.iam.security.SecretProtector;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class IdentitySourceClientRegistrationRepositoryTest {
    @Test
    void resolvesOnlyActiveExactRevisionAndDecryptsSecretAtLookup() {
        IdentitySource source = source();
        IdentitySourceRepository sources = mock(IdentitySourceRepository.class);
        SecretProtector secrets = mock(SecretProtector.class);
        when(sources.findById(source.getId())).thenReturn(Optional.of(source));
        when(secrets.reveal("ciphertext")).thenReturn("runtime-secret");
        var repository = new IdentitySourceClientRegistrationRepository(
                sources, secrets, new OidcNetworkAddressPolicy("localhost"));

        var registration = repository.findByRegistrationId(
                IdentitySourceClientRegistrationRepository.registrationId(source));

        assertThat(registration).isNotNull();
        assertThat(registration.getClientId()).isEqualTo("upstream-client");
        assertThat(registration.getClientSecret()).isEqualTo("runtime-secret");
        assertThat(registration.getProviderDetails().getAuthorizationUri()).isEqualTo("https://localhost/authorize");
        assertThat(registration.getProviderDetails().getJwkSetUri()).isEqualTo("https://localhost/jwks");
    }

    @Test
    void staleRevisionAndMalformedRegistrationFailClosed() {
        IdentitySource source = source();
        IdentitySourceRepository sources = mock(IdentitySourceRepository.class);
        when(sources.findById(source.getId())).thenReturn(Optional.of(source));
        var repository = new IdentitySourceClientRegistrationRepository(
                sources, mock(SecretProtector.class), new OidcNetworkAddressPolicy("localhost"));

        assertThatThrownBy(() -> repository.findByRegistrationId(source.getId() + ".0"))
                .isInstanceOf(FederatedAuthenticationException.class);
        assertThatThrownBy(() -> repository.findByRegistrationId("not-a-registration"))
                .isInstanceOf(FederatedAuthenticationException.class);
    }

    private static IdentitySource source() {
        IdentitySource source = new IdentitySource("tenant-a", "Customer IdP", "https://localhost",
                "https://localhost/.well-known/openid-configuration", "upstream-client", "ciphertext",
                List.of("openid", "profile"), List.of("RS256"),
                List.of("sub", "iss", "aud", "exp", "iat", "nonce"), List.of());
        source.applyValidatedMetadata("https://localhost/authorize", "https://localhost/token",
                "https://localhost/userinfo", "https://localhost/jwks", Instant.now());
        source.activate();
        return source;
    }
}
