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

    @Test
    void acceptsLoginAndPlatformClientTokensButRejectsTenantApplicationTokens() {
        assertThat(validator.validate(claims(Map.of())).hasErrors()).as("/auth/login token").isFalse();
        assertThat(validator.validate(claims(Map.of("client_id", "axiom-admin", "identity_kind", "workforce")))
                .hasErrors()).as("platform console token").isFalse();

        assertThat(validator.validate(claims(Map.of("client_id", "tenant-app-web", "application_id", "app",
                "roles", List.of("platform_admin")))).hasErrors()).as("tenant application token").isTrue();
        assertThat(validator.validate(claims(Map.of("client_id", "tenant-app-web"))).hasErrors())
                .as("non-platform client").isTrue();
        assertThat(validator.validate(claims(Map.of("application_id", "app"))).hasErrors())
                .as("application claim without client_id").isTrue();
        for (String exchangeClaim : List.of("act", "token_use", "authority_profile", "authority_id", "delegation_id")) {
            assertThat(validator.validate(claims(Map.of("client_id", "axiom-admin", exchangeClaim, "x"))).hasErrors())
                    .as(exchangeClaim).isTrue();
        }
    }

    @Test
    void reservedAudiencesAreCaseAndWhitespaceInsensitive() {
        assertThat(AxiomApiJwtValidator.isReservedAudience("axiom-api")).isTrue();
        assertThat(AxiomApiJwtValidator.isReservedAudience(" AXIOM-API ")).isTrue();
        assertThat(AxiomApiJwtValidator.isReservedAudience("agent:meridian:bff")).isFalse();
        assertThat(AxiomApiJwtValidator.isReservedAudience(null)).isFalse();
    }

    private static Jwt claims(Map<String, Object> extra) {
        Instant now = Instant.now();
        Map<String, Object> all = new java.util.HashMap<>(extra);
        all.put("sub", "admin");
        all.put("aud", List.of("axiom-api"));
        return new Jwt("signed", now, now.plusSeconds(60), Map.of("alg", "RS256", "typ", "at+jwt"), all);
    }

    private static Jwt token(List<String> audience, String type) {
        Instant now = Instant.now();
        Map<String, Object> headers = type == null ? Map.of("alg", "RS256") : Map.of("alg", "RS256", "typ", type);
        return new Jwt("signed", now, now.plusSeconds(60), headers, Map.of("sub", "admin", "aud", audience));
    }
}
