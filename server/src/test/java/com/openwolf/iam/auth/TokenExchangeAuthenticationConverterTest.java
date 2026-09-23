package com.openwolf.iam.auth;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class TokenExchangeAuthenticationConverterTest {
    private final TokenExchangeAuthenticationConverter converter = new TokenExchangeAuthenticationConverter();

    @AfterEach
    void clearContext() { SecurityContextHolder.clearContext(); }

    @Test
    void parsesStrictRfc8693RequestWithoutCallerOwnedGovernanceFields() {
        var actor = UsernamePasswordAuthenticationToken.authenticated("agent-client", "n/a", java.util.List.of());
        SecurityContextHolder.getContext().setAuthentication(actor);
        MockHttpServletRequest request = request();

        TokenExchangeAuthenticationToken result = (TokenExchangeAuthenticationToken) converter.convert(request);

        assertThat(result.getPrincipal()).isSameAs(actor);
        assertThat(result.subjectToken()).isEqualTo("customer-token");
        assertThat(result.audience()).isEqualTo("https://cards.internal");
        assertThat(result.requestedScopes()).containsExactly("cards:incident.read");
    }

    @Test
    void rejectsActorTokenOrCallerOwnedPurposeAndDelegation() {
        MockHttpServletRequest actorToken = request();
        actorToken.addParameter(TokenExchangeConstants.ACTOR_TOKEN, "untrusted-actor");
        assertThatThrownBy(() -> converter.convert(actorToken)).isInstanceOf(OAuth2AuthenticationException.class);

        MockHttpServletRequest purpose = request();
        purpose.addParameter(TokenExchangeConstants.PURPOSE, "caller-choice");
        assertThatThrownBy(() -> converter.convert(purpose)).isInstanceOf(OAuth2AuthenticationException.class);

        MockHttpServletRequest grant = request();
        grant.addParameter(TokenExchangeConstants.DELEGATION_ID, java.util.UUID.randomUUID().toString());
        assertThatThrownBy(() -> converter.convert(grant)).isInstanceOf(OAuth2AuthenticationException.class);
    }

    @Test
    void requiresExactlyOneAudienceOrResource() {
        MockHttpServletRequest missing = request();
        missing.removeParameter(TokenExchangeConstants.AUDIENCE);
        assertThatThrownBy(() -> converter.convert(missing)).isInstanceOf(OAuth2AuthenticationException.class);

        MockHttpServletRequest both = request();
        both.addParameter(TokenExchangeConstants.RESOURCE, "https://other.internal");
        assertThatThrownBy(() -> converter.convert(both)).isInstanceOf(OAuth2AuthenticationException.class);
    }

    private static MockHttpServletRequest request() {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/oauth/token");
        request.addParameter("grant_type", TokenExchangeConstants.GRANT_TYPE_VALUE);
        request.addParameter(TokenExchangeConstants.SUBJECT_TOKEN, "customer-token");
        request.addParameter(TokenExchangeConstants.SUBJECT_TOKEN_TYPE, TokenExchangeConstants.ACCESS_TOKEN_TYPE);
        request.addParameter(TokenExchangeConstants.AUDIENCE, "https://cards.internal");
        request.addParameter("scope", "cards:incident.read");
        return request;
    }
}
