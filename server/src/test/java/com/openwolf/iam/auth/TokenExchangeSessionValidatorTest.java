package com.openwolf.iam.auth;

import com.openwolf.iam.service.IamSessionService;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.jwt.Jwt;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

class TokenExchangeSessionValidatorTest {
    private final IamSessionService sessions = mock(IamSessionService.class);
    private final TokenExchangeSessionValidator validator = new TokenExchangeSessionValidator(sessions);

    @Test
    void originalClientCredentialsWorkloadMayProceedToAuthorityValidationWithoutSession() {
        Jwt token = workload(Map.of());

        assertThat(validator.validate(token).hasErrors()).isFalse();
        verifyNoInteractions(sessions);
    }

    @Test
    void sessionlessHumanIdentitiesStillFailClosed() {
        assertThat(validator.validate(token("customer", "customer-a", "customer-a", Map.of())).hasErrors()).isTrue();
        assertThat(validator.validate(token("workforce", "user-a", "public-client", Map.of())).hasErrors()).isTrue();
    }

    @Test
    void workloadContinuationCannotUseTheSessionlessEntryPath() {
        Jwt token = workload(Map.of(
                "act", Map.of("client_id", "source-agent"),
                "token_use", "exchange_subject",
                "authority_profile", "gateway_backend",
                "authority_id", UUID.randomUUID().toString()));

        assertThat(validator.validate(token).hasErrors()).isTrue();
    }

    @Test
    void malformedOriginalWorkloadCannotUseTheSessionlessEntryPath() {
        Jwt token = token("workload", "different-subject", "source-agent", Map.of());

        assertThat(validator.validate(token).hasErrors()).isTrue();
    }

    @Test
    void anyTokenWithSessionIdKeepsDurableSessionValidation() {
        UUID sessionId = UUID.randomUUID();
        Jwt token = workload(Map.of("sid", sessionId.toString()));
        when(sessions.active(eq(sessionId), eq("meridian"), any(Instant.class))).thenReturn(true);

        assertThat(validator.validate(token).hasErrors()).isFalse();
    }

    private static Jwt workload(Map<String, Object> extraClaims) {
        return token("workload", "source-agent", "source-agent", extraClaims);
    }

    private static Jwt token(String identityKind, String subject, String clientId,
                             Map<String, Object> extraClaims) {
        Jwt.Builder builder = Jwt.withTokenValue(UUID.randomUUID().toString())
                .header("alg", "RS256")
                .subject(subject)
                .audience(List.of("agent:meridian:source-agent"))
                .claim("tenant_id", "meridian")
                .claim("identity_kind", identityKind)
                .claim("client_id", clientId)
                .issuedAt(Instant.now().minusSeconds(5))
                .expiresAt(Instant.now().plusSeconds(60));
        extraClaims.forEach(builder::claim);
        return builder.build();
    }
}
