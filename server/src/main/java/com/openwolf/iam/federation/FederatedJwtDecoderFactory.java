package com.openwolf.iam.federation;

import com.openwolf.iam.entity.IdentitySource;
import com.openwolf.iam.repository.IdentitySourceRepository;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtDecoderFactory;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.jwt.JwtValidators;
import org.springframework.stereotype.Component;

/** Source-pinned JWKS decoder using the same connection-bound OIDC transport. */
@Component
public final class FederatedJwtDecoderFactory implements JwtDecoderFactory<ClientRegistration> {
    private final IdentitySourceRepository sources;
    private final IdentitySourceRevisionGuard guard;
    private final ConnectionBoundOidcTransport transport;

    public FederatedJwtDecoderFactory(IdentitySourceRepository sources,
                                      IdentitySourceRevisionGuard guard,
                                      ConnectionBoundOidcTransport transport) {
        this.sources = sources;
        this.guard = guard;
        this.transport = transport;
    }

    @Override
    public JwtDecoder createDecoder(ClientRegistration registration) {
        var key = IdentitySourceClientRegistrationRepository.RegistrationKey.parse(registration.getRegistrationId());
        IdentitySource source = guard.requireActive(key);
        NimbusJwtDecoder decoder = NimbusJwtDecoder.withJwkSetUri(registration.getProviderDetails().getJwkSetUri())
                .restOperations(transport.restOperations())
                .jwsAlgorithms(algorithms -> source.getAllowedSigningAlgorithms().stream()
                        .map(SignatureAlgorithm::from)
                        .forEach(algorithms::add))
                .build();
        decoder.setJwtValidator(new FencedJwtValidator(guard, key, source.getIssuer(), source.getClientId()));
        return decoder;
    }

    private static final class FencedJwtValidator implements OAuth2TokenValidator<Jwt> {
        private final IdentitySourceRevisionGuard guard;
        private final IdentitySourceClientRegistrationRepository.RegistrationKey key;
        private final OAuth2TokenValidator<Jwt> standard;
        private final String issuer;
        private final String clientId;

        private FencedJwtValidator(IdentitySourceRevisionGuard guard,
                                   IdentitySourceClientRegistrationRepository.RegistrationKey key,
                                   String issuer, String clientId) {
            this.guard = guard; this.key = key; this.issuer = issuer; this.clientId = clientId;
            this.standard = JwtValidators.createDefaultWithIssuer(issuer);
        }

        @Override
        public OAuth2TokenValidatorResult validate(Jwt token) {
            try {
                guard.requireActive(key);
            } catch (FederatedAuthenticationException ex) {
                return OAuth2TokenValidatorResult.failure(new OAuth2Error("invalid_request", "federated identity is not available", null));
            }
            if (!OidcAudienceRules.matches(token.getAudience(), clientId, token.getClaimAsString("azp"))) {
                return OAuth2TokenValidatorResult.failure(new OAuth2Error("invalid_token", "federated identity is not available", null));
            }
            return standard.validate(token);
        }
    }
}
