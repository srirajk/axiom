package com.openwolf.iam.auth;

import com.openwolf.iam.service.AgentExchangeAuthorityService;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.jwt.Jwt;

import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

class AgentExchangeTokenAuthorityValidatorTest {
    @Test
    void authorityStoreOutageFailsClosed() {
        AgentExchangeAuthorityService authority = mock(AgentExchangeAuthorityService.class);
        Jwt token = Jwt.withTokenValue("token").header("alg", "RS256")
                .subject("principal-a").audience(java.util.List.of("resource-a"))
                .claim("authority_profile", "gateway_backend")
                .issuedAt(Instant.now().minusSeconds(5)).expiresAt(Instant.now().plusSeconds(60)).build();
        org.mockito.Mockito.doThrow(new IllegalStateException("authority store unavailable"))
                .when(authority).requireValidIssuedToken(token);

        assertThat(new AgentExchangeTokenAuthorityValidator(authority).validate(token).hasErrors()).isTrue();
        verify(authority).requireValidIssuedToken(token);
    }
}
