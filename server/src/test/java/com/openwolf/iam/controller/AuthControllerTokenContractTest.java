package com.openwolf.iam.controller;

import com.openwolf.iam.auth.AxiomApiJwtValidator;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.proc.DefaultJOSEObjectTypeVerifier;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.JwsHeader;

import java.time.Instant;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class AuthControllerTokenContractTest {
    @Test
    void directLoginHeaderRoundTripsThroughTheAxiomApiDecoder() throws Exception {
        RSAKey key = new RSAKeyGenerator(2048).keyID("direct-login").generate();
        NimbusJwtEncoder encoder = new NimbusJwtEncoder(new ImmutableJWKSet<>(new JWKSet(key)));
        Instant now = Instant.now();
        String token = encoder.encode(JwtEncoderParameters.from(AuthController.accessTokenHeader(),
                JwtClaimsSet.builder().issuer("http://localhost:8086").subject("principal-1")
                        .audience(List.of(AxiomApiJwtValidator.AUDIENCE)).issuedAt(now)
                        .expiresAt(now.plusSeconds(300)).build())).getTokenValue();

        JwtDecoder decoder = configuredDecoder(key);
        ((NimbusJwtDecoder) decoder).setJwtValidator(new AxiomApiJwtValidator());

        assertThat(decoder.decode(token).getHeaders().get("typ")).isEqualTo("at+jwt");
    }

    @Test
    void wrongAccessTokenTypeIsRejectedByTheApiValidator() throws Exception {
        RSAKey key = new RSAKeyGenerator(2048).keyID("wrong-type").generate();
        NimbusJwtEncoder encoder = new NimbusJwtEncoder(new ImmutableJWKSet<>(new JWKSet(key)));
        Instant now = Instant.now();
        JwsHeader header = JwsHeader.with(SignatureAlgorithm.RS256).type("JWT").build();
        String token = encoder.encode(JwtEncoderParameters.from(header,
                JwtClaimsSet.builder().issuer("http://localhost:8086").subject("principal-1")
                        .audience(List.of(AxiomApiJwtValidator.AUDIENCE)).issuedAt(now)
                        .expiresAt(now.plusSeconds(300)).build())).getTokenValue();
        NimbusJwtDecoder decoder = configuredDecoder(key);
        decoder.setJwtValidator(new AxiomApiJwtValidator());

        assertThatThrownBy(() -> decoder.decode(token)).isInstanceOf(Exception.class);
    }

    private static NimbusJwtDecoder configuredDecoder(RSAKey key) {
        DefaultJWTProcessor<SecurityContext> processor = new DefaultJWTProcessor<>();
        processor.setJWSKeySelector(new JWSVerificationKeySelector<>(JWSAlgorithm.RS256,
                new ImmutableJWKSet<>(new JWKSet(key))));
        processor.setJWSTypeVerifier(new DefaultJOSEObjectTypeVerifier<>(new JOSEObjectType("at+jwt")));
        return new NimbusJwtDecoder(processor);
    }
}
