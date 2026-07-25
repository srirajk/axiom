package com.openwolf.iam.auth;

import com.openwolf.iam.service.IamSessionService;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2TokenIntrospectionAuthenticationToken;

import java.time.Instant;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.when;

class SessionAwareIntrospectionAuthenticationProviderTest {
    private final OAuth2AuthorizationService authorizations = mock(OAuth2AuthorizationService.class);
    private final IamSessionService sessions = mock(IamSessionService.class);
    private final JwtDecoder decoder = mock(JwtDecoder.class);
    private final Authentication caller = new TestingAuthenticationToken("introspector", "secret");
    private final UUID sessionId = UUID.randomUUID();
    private final Jwt jwt = Jwt.withTokenValue("manual-token").header("alg", "RS256").subject("principal-a")
            .claim("tenant_id", "tenant-a").claim("sid", sessionId.toString())
            .claim("client_id", "axiom-admin").issuedAt(Instant.now().minusSeconds(5))
            .expiresAt(Instant.now().plusSeconds(300)).build();

    @Test
    void manualJwtIsActiveBeforeRevocationAndInactiveAfter() {
        when(authorizations.findByToken("manual-token", org.springframework.security.oauth2.server.authorization.OAuth2TokenType.ACCESS_TOKEN))
                .thenReturn(null);
        when(decoder.decode("manual-token")).thenReturn(jwt);
        when(sessions.active(eq(sessionId), eq("tenant-a"), any(Instant.class))).thenReturn(true, false);
        SessionAwareIntrospectionAuthenticationProvider provider = provider();

        assertThat(claims(provider).get("active")).isEqualTo(true);
        assertThat(claims(provider).get("active")).isEqualTo(false);
    }

    @Test
    void untrustedOrSidlessManualJwtIsInactive() {
        when(authorizations.findByToken(any(), any())).thenReturn(null);
        when(decoder.decode("manual-token")).thenThrow(new JwtException("signature rejected"));
        assertThat(claims(provider()).get("active")).isEqualTo(false);

        Jwt sidless = Jwt.withTokenValue("manual-token").header("alg", "RS256").subject("principal-a")
                .claim("tenant_id", "tenant-a").issuedAt(Instant.now().minusSeconds(5))
                .expiresAt(Instant.now().plusSeconds(300)).build();
        doReturn(sidless).when(decoder).decode("manual-token");
        assertThat(claims(provider()).get("active")).isEqualTo(false);

        Jwt expired = Jwt.withTokenValue("manual-token").header("alg", "RS256").subject("principal-a")
                .claim("tenant_id", "tenant-a").claim("sid", sessionId.toString())
                .issuedAt(Instant.now().minusSeconds(60)).expiresAt(Instant.now().minusSeconds(1)).build();
        doReturn(expired).when(decoder).decode("manual-token");
        assertThat(claims(provider()).get("active")).isEqualTo(false);
    }

    private SessionAwareIntrospectionAuthenticationProvider provider() {
        AuthenticationProviderStub delegate = new AuthenticationProviderStub();
        return new SessionAwareIntrospectionAuthenticationProvider(delegate, authorizations, sessions, decoder);
    }

    private Map<String, Object> claims(SessionAwareIntrospectionAuthenticationProvider provider) {
        Authentication input = new OAuth2TokenIntrospectionAuthenticationToken("manual-token", caller,
                "access_token", Map.of());
        return ((OAuth2TokenIntrospectionAuthenticationToken) provider.authenticate(input)).getTokenClaims().getClaims();
    }

    private static final class AuthenticationProviderStub implements org.springframework.security.authentication.AuthenticationProvider {
        @Override public Authentication authenticate(Authentication authentication) { return authentication; }
        @Override public boolean supports(Class<?> authentication) { return true; }
    }
}
