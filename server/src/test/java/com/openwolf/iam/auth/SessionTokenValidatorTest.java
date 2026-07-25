package com.openwolf.iam.auth;

import com.openwolf.iam.service.IamSessionService;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.jwt.Jwt;

import java.time.Instant;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class SessionTokenValidatorTest {
    @Test
    void revokedOrUnknownSessionFailsClosed() {
        IamSessionService sessions = mock(IamSessionService.class);
        UUID sessionId = UUID.randomUUID();
        SessionTokenValidator validator = new SessionTokenValidator(sessions);
        Jwt token = Jwt.withTokenValue("token").header("alg", "RS256").subject("principal-a")
                .claim("tenant_id", "tenant-a").claim("sid", sessionId.toString())
                .issuedAt(Instant.now().minusSeconds(5)).expiresAt(Instant.now().plusSeconds(60)).build();
        when(sessions.active(sessionId, "tenant-a", token.getExpiresAt())).thenReturn(false);

        assertThat(validator.validate(token).hasErrors()).isTrue();
    }

    @Test
    void activeSessionIsAccepted() {
        IamSessionService sessions = mock(IamSessionService.class);
        UUID sessionId = UUID.randomUUID();
        SessionTokenValidator validator = new SessionTokenValidator(sessions);
        Jwt token = Jwt.withTokenValue("token").header("alg", "RS256").subject("principal-a")
                .claim("tenant_id", "tenant-a").claim("sid", sessionId.toString())
                .issuedAt(Instant.now().minusSeconds(5)).expiresAt(Instant.now().plusSeconds(60)).build();
        when(sessions.active(org.mockito.ArgumentMatchers.eq(sessionId), org.mockito.ArgumentMatchers.eq("tenant-a"),
                org.mockito.ArgumentMatchers.any(Instant.class))).thenReturn(true);

        assertThat(validator.validate(token).hasErrors()).isFalse();
    }

    @Test
    void recoveryTokenUsesRecoverySessionMetadataBoundary() {
        IamSessionService sessions = mock(IamSessionService.class);
        UUID sessionId = UUID.randomUUID();
        SessionTokenValidator validator = new SessionTokenValidator(sessions);
        Jwt token = Jwt.withTokenValue("token").header("alg", "RS256").subject("recovery:" + sessionId)
                .claim("tenant_id", "tenant-a").claim("sid", sessionId.toString())
                .claim("recovery", true).claim("recovery_scope", "identity-admin")
                .issuedAt(Instant.now().minusSeconds(5)).expiresAt(Instant.now().plusSeconds(60)).build();
        when(sessions.active(org.mockito.ArgumentMatchers.eq(sessionId), org.mockito.ArgumentMatchers.eq("tenant-a"),
                org.mockito.ArgumentMatchers.any(Instant.class), org.mockito.ArgumentMatchers.eq(true),
                org.mockito.ArgumentMatchers.eq("identity-admin"))).thenReturn(true);

        assertThat(validator.validate(token).hasErrors()).isFalse();
    }
}
