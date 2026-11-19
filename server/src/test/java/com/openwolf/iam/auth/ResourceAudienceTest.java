package com.openwolf.iam.auth;

import java.util.List;
import java.util.Map;
import java.time.Instant;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class ResourceAudienceTest {
    private static final String GATEWAY = "argus-gateway-dev";
    private static final List<String> PREFIX = List.of("https://assistants-dev.example.test/");
    private static final String BLOCK_A = "https://assistants-dev.example.test/v1/mcp/quickstart/block-a";
    private static final String BLOCK_B = "https://assistants-dev.example.test/v1/mcp/quickstart/block-b";

    @Test
    void aResourceBelowAPrefixIsNamedFirstAndTheApplicationAudienceStays() {
        assertThat(ResourceAudience.of(BLOCK_A, GATEWAY, PREFIX)).containsExactly(BLOCK_A, GATEWAY);
    }

    @Test
    void everyOtherRequestKeepsTheApplicationAudienceAlone() {
        assertThat(ResourceAudience.of(null, GATEWAY, PREFIX)).containsExactly(GATEWAY);
        assertThat(ResourceAudience.of(GATEWAY, GATEWAY, PREFIX)).containsExactly(GATEWAY);
        // the prefix itself is the whole host: the application, not one resource on it
        assertThat(ResourceAudience.of(PREFIX.getFirst(), GATEWAY, PREFIX)).containsExactly(GATEWAY);
        // an exact registration names the application (Argus MCP's own resource)
        assertThat(ResourceAudience.of("https://api.example.test/mcp", GATEWAY, List.of("https://api.example.test/mcp")))
                .containsExactly(GATEWAY);
        assertThat(ResourceAudience.of(BLOCK_A + "?x=1", GATEWAY, PREFIX)).containsExactly(GATEWAY);
        assertThat(ResourceAudience.of("https://other.example.test/v1/mcp/q/b", GATEWAY, PREFIX)).containsExactly(GATEWAY);
        assertThat(ResourceAudience.of(BLOCK_A, GATEWAY, List.of())).containsExactly(GATEWAY);
    }

    @Test
    void theResourceBoundAtAuthorizationWinsAndATokenRequestCannotChangeIt() {
        assertThat(ResourceAudience.requested(context(BLOCK_A, null))).isEqualTo(BLOCK_A);
        assertThat(ResourceAudience.requested(context(BLOCK_A, BLOCK_A))).isEqualTo(BLOCK_A);
        assertThat(ResourceAudience.requested(context(null, BLOCK_B))).isEqualTo(BLOCK_B);
        assertThat(ResourceAudience.requested(context(null, null))).isNull();
        assertThatThrownBy(() -> ResourceAudience.requested(context(BLOCK_A, BLOCK_B)))
                .isInstanceOf(OAuth2AuthenticationException.class)
                .satisfies(e -> assertThat(((OAuth2AuthenticationException) e).getError().getErrorCode())
                        .isEqualTo("invalid_target"));
        assertThatThrownBy(() -> ResourceAudience.requested(context(new String[] {BLOCK_A, BLOCK_B}, null)))
                .isInstanceOf(OAuth2AuthenticationException.class);
    }

    @Test
    void aTokenIsIssuedForItsApplicationAloneOrWithOneResourceBelowItsPrefix() {
        assertThat(ResourceAudience.issuedFor(jwt(GATEWAY), GATEWAY, PREFIX)).isTrue();
        assertThat(ResourceAudience.issuedFor(jwt(BLOCK_A, GATEWAY), GATEWAY, PREFIX)).isTrue();
        assertThat(ResourceAudience.issuedFor(jwt(BLOCK_A, GATEWAY), GATEWAY, List.of())).isFalse();
        assertThat(ResourceAudience.issuedFor(jwt(GATEWAY, BLOCK_A), GATEWAY, PREFIX)).isFalse();
        assertThat(ResourceAudience.issuedFor(jwt("https://evil.example.test/x", GATEWAY), GATEWAY, PREFIX)).isFalse();
        assertThat(ResourceAudience.issuedFor(jwt(BLOCK_A, "other-gateway"), GATEWAY, PREFIX)).isFalse();
        assertThat(ResourceAudience.issuedFor(jwt(BLOCK_A, BLOCK_B, GATEWAY), GATEWAY, PREFIX)).isFalse();
        assertThat(ResourceAudience.applicationAudience(List.of(BLOCK_A, GATEWAY))).isEqualTo(GATEWAY);
        assertThat(ResourceAudience.applicationAudience(List.of(GATEWAY))).isEqualTo(GATEWAY);
        assertThat(ResourceAudience.applicationAudience(List.of(BLOCK_A, BLOCK_B, GATEWAY))).isEmpty();
    }

    @Test
    void belowNeedsAPrefixRegistrationAndAStrictlyLongerPathOnTheSameHost() {
        assertThat(ApplicationResourceUris.below(BLOCK_A, PREFIX)).isTrue();
        assertThat(ApplicationResourceUris.below("https://ASSISTANTS-DEV.example.test/v1/mcp/q/b", PREFIX)).isTrue();
        assertThat(ApplicationResourceUris.below(PREFIX.getFirst(), PREFIX)).isFalse();
        assertThat(ApplicationResourceUris.below("https://assistants-dev.example.test:8443/v1/mcp/q/b", PREFIX)).isFalse();
        assertThat(ApplicationResourceUris.below("http://assistants-dev.example.test/v1/mcp/q/b", PREFIX)).isFalse();
        assertThat(ApplicationResourceUris.below(BLOCK_A, List.of(BLOCK_A))).isFalse();
        assertThat(ApplicationResourceUris.below("not a uri", PREFIX)).isFalse();
    }

    private static Jwt jwt(String... audiences) {
        return Jwt.withTokenValue("t").header("alg", "none").subject("person")
                .audience(List.of(audiences)).issuedAt(Instant.now()).expiresAt(Instant.now().plusSeconds(60)).build();
    }

    private static JwtEncodingContext context(Object authorized, String asked) {
        JwtEncodingContext context = mock(JwtEncodingContext.class);
        OAuth2Authorization authorization = mock(OAuth2Authorization.class);
        OAuth2AuthorizationRequest request = OAuth2AuthorizationRequest.authorizationCode()
                .authorizationUri("https://idp.example.test/oauth/authorize").clientId("client")
                .additionalParameters(authorized == null ? Map.of() : Map.of("resource", authorized)).build();
        when(authorization.getAttribute(OAuth2AuthorizationRequest.class.getName())).thenReturn(request);
        when(context.getAuthorization()).thenReturn(authorization);
        OAuth2AuthorizationCodeAuthenticationToken grant = new OAuth2AuthorizationCodeAuthenticationToken("code",
                mock(org.springframework.security.core.Authentication.class), null,
                asked == null ? Map.of() : Map.of("resource", asked));
        when(context.getAuthorizationGrant()).thenReturn(grant);
        return context;
    }
}
