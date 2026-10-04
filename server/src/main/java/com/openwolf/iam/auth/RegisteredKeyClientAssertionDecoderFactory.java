package com.openwolf.iam.auth;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import com.openwolf.iam.service.ClientAssertionKeys;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.jose.jws.JwsAlgorithm;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtDecoderFactory;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.server.authorization.authentication.JwtClientAssertionDecoderFactory;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.HexFormat;

/**
 * Verifies {@code private_key_jwt} client assertions (RFC 7523 section 3) against the public keys registered inline
 * on the client, with the framework's issuer/subject/audience/expiry checks plus two local rules:
 * <ul>
 *   <li>the assertion lives at most five minutes ({@code exp - iat}, or {@code exp - now} without {@code iat});</li>
 *   <li>{@code jti} is required and single-use: it is recorded in Redis until the assertion expires, and a second
 *   presentation is {@code invalid_client} (replay). If Redis is unavailable the assertion is refused.</li>
 * </ul>
 */
public final class RegisteredKeyClientAssertionDecoderFactory implements JwtDecoderFactory<RegisteredClient> {
    static final Duration MAX_ASSERTION_LIFETIME = Duration.ofMinutes(5);
    private static final OAuth2Error INVALID_CLIENT = new OAuth2Error(OAuth2ErrorCodes.INVALID_CLIENT);

    private final StringRedisTemplate redis;
    private final String keyPrefix;
    private final Clock clock;

    public RegisteredKeyClientAssertionDecoderFactory(StringRedisTemplate redis, String keyPrefix) {
        this(redis, keyPrefix, Clock.systemUTC());
    }

    RegisteredKeyClientAssertionDecoderFactory(StringRedisTemplate redis, String keyPrefix, Clock clock) {
        this.redis = redis;
        this.keyPrefix = keyPrefix;
        this.clock = clock;
    }

    @Override
    public JwtDecoder createDecoder(RegisteredClient client) {
        JWKSet keys = ClientAssertionKeys.keys(client);
        JwsAlgorithm algorithm = client.getClientSettings().getTokenEndpointAuthenticationSigningAlgorithm();
        if (keys == null || algorithm == null) throw new OAuth2AuthenticationException(INVALID_CLIENT);
        DefaultJWTProcessor<SecurityContext> processor = new DefaultJWTProcessor<>();
        processor.setJWSKeySelector(new JWSVerificationKeySelector<>(JWSAlgorithm.parse(algorithm.getName()),
                new ImmutableJWKSet<>(keys)));
        NimbusJwtDecoder decoder = new NimbusJwtDecoder(processor);
        decoder.setJwtValidator(new DelegatingOAuth2TokenValidator<>(
                JwtClientAssertionDecoderFactory.DEFAULT_JWT_VALIDATOR_FACTORY.apply(client),
                this::boundedLifetime, assertion -> singleUse(client, assertion)));
        return decoder;
    }

    private OAuth2TokenValidatorResult boundedLifetime(Jwt assertion) {
        Instant expiry = assertion.getExpiresAt();
        Instant start = assertion.getIssuedAt() != null ? assertion.getIssuedAt() : clock.instant();
        if (expiry == null || Duration.between(start, expiry).compareTo(MAX_ASSERTION_LIFETIME) > 0) {
            return OAuth2TokenValidatorResult.failure(INVALID_CLIENT);
        }
        return OAuth2TokenValidatorResult.success();
    }

    private OAuth2TokenValidatorResult singleUse(RegisteredClient client, Jwt assertion) {
        String jti = assertion.getId();
        if (jti == null || jti.isBlank() || assertion.getExpiresAt() == null) {
            return OAuth2TokenValidatorResult.failure(INVALID_CLIENT);
        }
        Duration remaining = Duration.between(clock.instant(), assertion.getExpiresAt()).plusSeconds(60);
        if (remaining.isNegative() || remaining.isZero()) return OAuth2TokenValidatorResult.failure(INVALID_CLIENT);
        String key = keyPrefix + ":client-assertion-jti:" + sha256(client.getClientId() + "\u0000" + jti);
        try {
            Boolean first = redis.opsForValue().setIfAbsent(key, "1", remaining);
            return Boolean.TRUE.equals(first) ? OAuth2TokenValidatorResult.success()
                    : OAuth2TokenValidatorResult.failure(INVALID_CLIENT);
        } catch (RuntimeException unavailable) {
            // Replay protection cannot be proven without the store: refuse rather than accept a possible replay.
            return OAuth2TokenValidatorResult.failure(INVALID_CLIENT);
        }
    }

    private static String sha256(String value) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8)));
        } catch (java.security.NoSuchAlgorithmException unavailable) {
            throw new IllegalStateException(unavailable);
        }
    }
}
