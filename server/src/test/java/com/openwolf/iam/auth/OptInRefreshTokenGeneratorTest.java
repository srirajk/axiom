package com.openwolf.iam.auth;

import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.core.*;
import org.springframework.security.oauth2.server.authorization.*;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.settings.*;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenContext;
import java.time.*;
import java.util.Set;
import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.*;

class OptInRefreshTokenGeneratorTest {
    @Test void rotationPreservesTheInitialAbsoluteExpiryAndExpiredFamilyIsInvalidGrant() {
        Instant now=Instant.parse("2026-10-28T12:00:00Z"),end=now.plusSeconds(3600);
        var client=RegisteredClient.withId("id").clientId("public").clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE).authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .redirectUri("http://127.0.0.1/callback").scope("offline_access")
                .clientSettings(ClientSettings.builder().setting(OptInRefreshTokenGenerator.ABSOLUTE_LIFETIME,true).build())
                .tokenSettings(TokenSettings.builder().reuseRefreshTokens(false).refreshTokenTimeToLive(Duration.ofDays(30)).build()).build();
        OAuth2TokenContext context=mock(OAuth2TokenContext.class);when(context.getRegisteredClient()).thenReturn(client);
        when(context.getTokenType()).thenReturn(OAuth2TokenType.REFRESH_TOKEN);
        when(context.getAuthorizedScopes()).thenReturn(Set.of("offline_access"));
        var family=OAuth2Authorization.withRegisteredClient(client).principalName("person").authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizedScopes(Set.of("offline_access")).refreshToken(new OAuth2RefreshToken("old",now.minusSeconds(60),end)).build();
        when(context.getAuthorization()).thenReturn(family);
        var result=new OptInRefreshTokenGenerator(Clock.fixed(now,ZoneOffset.UTC)).generate(context);
        assertThat(result.getExpiresAt()).isEqualTo(end);assertThat(result.getTokenValue()).isNotEqualTo("old");
        assertThatThrownBy(()->new OptInRefreshTokenGenerator(Clock.fixed(end,ZoneOffset.UTC)).generate(context))
                .isInstanceOfSatisfying(OAuth2AuthenticationException.class,e->assertThat(e.getError().getErrorCode()).isEqualTo("invalid_grant"));
        when(context.getAuthorization()).thenReturn(null);when(context.getAuthorizedScopes()).thenReturn(Set.of("openid"));
        assertThat(new OptInRefreshTokenGenerator().generate(context)).isNull();
    }
}
