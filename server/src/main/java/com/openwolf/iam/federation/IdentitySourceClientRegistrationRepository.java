package com.openwolf.iam.federation;

import com.openwolf.iam.entity.IdentitySource;
import com.openwolf.iam.repository.IdentitySourceRepository;
import com.openwolf.iam.security.SecretProtector;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.stereotype.Component;

import java.net.URI;
import java.util.Iterator;
import java.util.Map;
import java.util.UUID;

/** Dynamic ACTIVE source registrations. The registration id pins source UUID and revision. */
@Component
public final class IdentitySourceClientRegistrationRepository implements ClientRegistrationRepository,
        Iterable<ClientRegistration> {
    private final IdentitySourceRepository sources;
    private final SecretProtector secrets;
    private final OidcNetworkAddressPolicy networkPolicy;

    public IdentitySourceClientRegistrationRepository(IdentitySourceRepository sources,
                                                       SecretProtector secrets,
                                                       OidcNetworkAddressPolicy networkPolicy) {
        this.sources = sources;
        this.secrets = secrets;
        this.networkPolicy = networkPolicy;
    }

    @Override
    public ClientRegistration findByRegistrationId(String registrationId) {
        try {
            RegistrationKey key = RegistrationKey.parse(registrationId);
            IdentitySource source = sources.findById(key.sourceId()).orElse(null);
            if (source == null || source.getStatus() != IdentitySource.Status.ACTIVE
                    || source.getRevision() != key.revision()) {
                throw new FederatedAuthenticationException();
            }
            if (source.getAuthorizationEndpoint() == null || source.getTokenEndpoint() == null
                    || source.getJwksUri() == null) {
                throw new FederatedAuthenticationException();
            }
            networkPolicy.validate(URI.create(source.getIssuer()), "issuer");
            networkPolicy.validate(URI.create(source.getAuthorizationEndpoint()), "authorization endpoint");
            networkPolicy.validate(URI.create(source.getTokenEndpoint()), "token endpoint");
            networkPolicy.validate(URI.create(source.getJwksUri()), "JWKS endpoint");
            if (source.getUserinfoEndpoint() != null) {
                networkPolicy.validate(URI.create(source.getUserinfoEndpoint()), "userinfo endpoint");
            }
            return ClientRegistration.withRegistrationId(registrationId)
                    .clientId(source.getClientId())
                    .clientSecret(secrets.reveal(source.getClientSecretCiphertext()))
                    .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                    .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                    .redirectUri("{baseUrl}/login/oauth2/code/{registrationId}")
                    .scope(source.getRequestedScopes())
                    .authorizationUri(source.getAuthorizationEndpoint())
                    .tokenUri(source.getTokenEndpoint())
                    .jwkSetUri(source.getJwksUri())
                    .userInfoUri(source.getUserinfoEndpoint())
                    .providerConfigurationMetadata(Map.of("issuer", source.getIssuer()))
                    .userNameAttributeName("sub")
                    .clientName(source.getDisplayName())
                    .build();
        } catch (FederatedAuthenticationException ex) {
            throw ex;
        } catch (RuntimeException ex) {
            throw new FederatedAuthenticationException(ex);
        }
    }

    @Override
    public Iterator<ClientRegistration> iterator() {
        return sources.findAll().stream()
                .filter(source -> source.getStatus() == IdentitySource.Status.ACTIVE)
                .map(source -> findByRegistrationId(registrationId(source)))
                .filter(java.util.Objects::nonNull)
                .iterator();
    }

    public static String registrationId(IdentitySource source) {
        return source.getId() + "." + source.getRevision();
    }

    public record RegistrationKey(UUID sourceId, long revision) {
        static RegistrationKey parse(String value) {
            if (value == null) return invalid();
            int separator = value.lastIndexOf('.');
            if (separator <= 0 || separator == value.length() - 1) return invalid();
            try {
                return new RegistrationKey(UUID.fromString(value.substring(0, separator)),
                        Long.parseLong(value.substring(separator + 1)));
            } catch (RuntimeException ex) {
                return invalid();
            }
        }

        private static RegistrationKey invalid() {
            throw new IllegalArgumentException("invalid identity source registration");
        }
    }
}
