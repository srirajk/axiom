package com.openwolf.iam.authority;

import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationGrantAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContextHolder;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.security.oauth2.server.authorization.token.DefaultOAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;

import java.time.Duration;
import java.util.Set;
import java.util.UUID;

/**
 * Mints and records an access token for a Phase 3 extension grant whose claims were resolved from durable state.
 * The OAuth authorization record (Redis) is expiring protocol state only; authority lives in PostgreSQL.
 */
public final class AuthorityTokenIssuer {
    private final OAuth2AuthorizationService authorizations;
    private final OAuth2TokenGenerator<? extends OAuth2Token> generator;

    public AuthorityTokenIssuer(OAuth2AuthorizationService authorizations,
                                OAuth2TokenGenerator<? extends OAuth2Token> generator) {
        this.authorizations = authorizations;
        this.generator = generator;
    }

    public record Issued(OAuth2AccessToken accessToken, Jwt jwt) {}

    public Issued issue(OAuth2ClientAuthenticationToken client, OAuth2AuthorizationGrantAuthenticationToken grant,
                        AuthorizationGrantType grantType, String principalName, Set<String> scopes, Duration ttl) {
        if (ttl.isZero() || ttl.isNegative()) throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_GRANT);
        RegisteredClient registered = client.getRegisteredClient();
        RegisteredClient bounded = RegisteredClient.from(registered)
                .tokenSettings(TokenSettings.withSettings(registered.getTokenSettings().getSettings())
                        .accessTokenTimeToLive(ttl).build())
                .build();
        OAuth2Authorization pending = OAuth2Authorization.withRegisteredClient(registered)
                .id(UUID.randomUUID().toString())
                .principalName(principalName)
                .authorizationGrantType(grantType)
                .authorizedScopes(scopes)
                .build();
        OAuth2Token generated = generator.generate(DefaultOAuth2TokenContext.builder()
                .registeredClient(bounded)
                .principal(client)
                .authorizationServerContext(AuthorizationServerContextHolder.getContext())
                .authorization(pending)
                .authorizedScopes(scopes)
                .tokenType(OAuth2TokenType.ACCESS_TOKEN)
                .authorizationGrantType(grantType)
                .authorizationGrant(grant)
                .build());
        if (!(generated instanceof Jwt jwt)) {
            throw new OAuth2AuthenticationException(new OAuth2Error(OAuth2ErrorCodes.SERVER_ERROR));
        }
        OAuth2AccessToken access = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, jwt.getTokenValue(),
                jwt.getIssuedAt(), jwt.getExpiresAt(), scopes);
        authorizations.save(OAuth2Authorization.from(pending)
                .token(access, metadata -> metadata.put(OAuth2Authorization.Token.CLAIMS_METADATA_NAME, jwt.getClaims()))
                .build());
        return new Issued(access, jwt);
    }
}
