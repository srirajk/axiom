package com.openwolf.iam.auth;

import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.jwt.Jwt;

import java.time.Instant;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class AxiomApiJwtValidatorTest {

    private final AxiomApiJwtValidator validator = new AxiomApiJwtValidator();

    @Test
    void acceptsOnlyAdminAudienceAndExactAccessTokenType() {
        assertThat(validator.validate(token(List.of("axiom-api"), "at+jwt")).hasErrors()).isFalse();
        assertThat(validator.validate(token(List.of("probata-api"), "at+jwt")).hasErrors()).isTrue();
        assertThat(validator.validate(token(List.of("axiom-api"), "tenant-delegation+jwt")).hasErrors()).isTrue();
        assertThat(validator.validate(token(List.of("axiom-api"), "JWT")).hasErrors()).isTrue();
        assertThat(validator.validate(token(List.of("axiom-api"), null)).hasErrors()).isTrue();
    }

    private static Jwt token(List<String> audience, String type) {
        Instant now = Instant.now();
        Map<String, Object> headers = type == null ? Map.of("alg", "RS256") : Map.of("alg", "RS256", "typ", type);
        return new Jwt("signed", now, now.plusSeconds(60), headers, Map.of("sub", "admin", "aud", audience));
    }
}
