package com.openwolf.iam.auth;

import com.openwolf.iam.entity.TenantApplicationClient;
import com.openwolf.iam.service.AuditService;
import com.openwolf.iam.service.CiamDelegationAuthorityService;
import com.openwolf.iam.service.AgentExchangeAuthorityService;
import com.openwolf.iam.service.TenantApplicationService;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AccessTokenAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContextHolder;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.security.oauth2.server.authorization.token.DefaultOAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;

import java.time.Duration;
import java.time.Instant;
import java.util.Collection;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

/** Issues short-lived, audience-bound dual-principal tokens using RFC 8693. */
public final class TokenExchangeAuthenticationProvider implements AuthenticationProvider {
    private static final OAuth2Error INVALID_CLIENT = new OAuth2Error(OAuth2ErrorCodes.INVALID_CLIENT);
    private static final OAuth2Error INVALID_GRANT = new OAuth2Error(OAuth2ErrorCodes.INVALID_GRANT);
    private static final OAuth2Error INVALID_SCOPE = new OAuth2Error(OAuth2ErrorCodes.INVALID_SCOPE);
    private static final OAuth2Error INVALID_TARGET = new OAuth2Error("invalid_target");
    private static final OAuth2Error UNAUTHORIZED_CLIENT = new OAuth2Error(OAuth2ErrorCodes.UNAUTHORIZED_CLIENT);

    private final OAuth2AuthorizationService authorizations;
    private final OAuth2TokenGenerator<? extends OAuth2Token> tokenGenerator;
    private final JwtDecoder subjectDecoder;
    private final TenantApplicationService applications;
    private final AuditService audit;
    private final AgentExchangeAuthorityService exchangeAuthority;
    private final Duration maximumTtl;

    public TokenExchangeAuthenticationProvider(OAuth2AuthorizationService authorizations,
                                               OAuth2TokenGenerator<? extends OAuth2Token> tokenGenerator,
                                               JwtDecoder subjectDecoder,
                                               TenantApplicationService applications,
                                               AuditService audit,
                                               AgentExchangeAuthorityService exchangeAuthority,
                                               @Value("${iam.oauth2.token-exchange.ttl:PT5M}") Duration maximumTtl) {
        this.authorizations = authorizations;
        this.tokenGenerator = tokenGenerator;
        this.subjectDecoder = subjectDecoder;
        this.applications = applications;
        this.audit = audit;
        this.exchangeAuthority = exchangeAuthority;
        this.maximumTtl = maximumTtl;
        if (maximumTtl.isNegative() || maximumTtl.isZero() || maximumTtl.compareTo(Duration.ofMinutes(10)) > 0) {
            throw new IllegalArgumentException("token exchange TTL must be between one second and ten minutes");
        }
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        TokenExchangeAuthenticationToken exchange = (TokenExchangeAuthenticationToken) authentication;
        OAuth2ClientAuthenticationToken actor = authenticatedClient(exchange.getPrincipal());
        RegisteredClient actorClient = actor.getRegisteredClient();
        if (actorClient == null || !actorClient.getAuthorizationGrantTypes().contains(TokenExchangeConstants.GRANT_TYPE)) {
            fail(UNAUTHORIZED_CLIENT);
        }

        TenantApplicationService.ClientAuthority actorAuthority = applications.activeAuthority(actorClient.getClientId())
                .filter(authority -> authority.clientType() == TenantApplicationClient.Type.CONFIDENTIAL_SERVICE)
                .orElseThrow(() -> new OAuth2AuthenticationException(UNAUTHORIZED_CLIENT));
        try {
        if (!actorClient.getScopes().containsAll(exchange.requestedScopes())
                || !actorAuthority.scopes().containsAll(exchange.requestedScopes())) fail(INVALID_SCOPE);
        Jwt subject = decodeSubject(exchange.subjectToken());
        AgentExchangeAuthorityService.ResolvedAuthority authority;
        try {
            authority = exchangeAuthority.resolve(subject, actorClient.getClientId(),
                    exchange.audience(), exchange.requestedScopes());
        } catch (RuntimeException denied) {
            if (denied instanceof OAuth2AuthenticationException oauth) throw oauth;
            throw new OAuth2AuthenticationException(INVALID_GRANT, denied);
        }
        String tenantId = authority.tenantId();
        if (!actorAuthority.tenantId().equals(tenantId)
                || !authority.audience().equals(exchange.audience())
                || !authority.scopes().containsAll(exchange.requestedScopes())) fail(INVALID_GRANT);

        Instant now = Instant.now();
        Instant subjectExpiry = subject.getExpiresAt();
        if (subjectExpiry == null || !subjectExpiry.isAfter(now)) fail(INVALID_GRANT);
        Duration ttl = minimum(maximumTtl, Duration.between(now, subjectExpiry));
        if (authority.authorityExpiresAt() != null) {
            ttl = minimum(ttl, Duration.between(now, authority.authorityExpiresAt()));
        }
        if (ttl.isZero() || ttl.isNegative()) fail(INVALID_GRANT);
        RegisteredClient boundedClient = RegisteredClient.from(actorClient)
                .tokenSettings(TokenSettings.withSettings(actorClient.getTokenSettings().getSettings())
                        .accessTokenTimeToLive(ttl).build())
                .build();

        exchange.bindAuthority(new TokenExchangeAuthenticationToken.AuthorityContext(
                subject, exchange.audience(), authority.purpose(), authority.profile().name().toLowerCase(),
                authority.authorityId(), authority.delegationId(), authority.tokenUse().name().toLowerCase(),
                authority.identityKind(), authority.actingWorkload().getId().toString(),
                authority.actingWorkload().getWorkloadRef(), authority.actingWorkload().getOauthClientId()));
        OAuth2Authorization pending = OAuth2Authorization.withRegisteredClient(actorClient)
                .id(UUID.randomUUID().toString())
                .principalName(subject.getSubject())
                .authorizationGrantType(TokenExchangeConstants.GRANT_TYPE)
                .authorizedScopes(exchange.requestedScopes())
                .attribute(TokenExchangeConstants.CONTEXT_AUTHORITY_ID, authority.authorityId())
                .build();

        DefaultOAuth2TokenContext tokenContext = DefaultOAuth2TokenContext.builder()
                .registeredClient(boundedClient)
                .principal(actor)
                .authorizationServerContext(AuthorizationServerContextHolder.getContext())
                .authorization(pending)
                .authorizedScopes(exchange.requestedScopes())
                .tokenType(OAuth2TokenType.ACCESS_TOKEN)
                .authorizationGrantType(TokenExchangeConstants.GRANT_TYPE)
                .authorizationGrant(exchange)
                .put(TokenExchangeConstants.CONTEXT_SUBJECT, subject)
                .put(TokenExchangeConstants.CONTEXT_AUDIENCE, exchange.audience())
                .put(TokenExchangeConstants.CONTEXT_PURPOSE, authority.purpose())
                .put(TokenExchangeConstants.CONTEXT_AUTHORITY_PROFILE, authority.profile().name().toLowerCase())
                .put(TokenExchangeConstants.CONTEXT_AUTHORITY_ID, authority.authorityId())
                .put(TokenExchangeConstants.CONTEXT_TOKEN_USE, authority.tokenUse().name().toLowerCase())
                .put(TokenExchangeConstants.CONTEXT_IDENTITY_KIND, authority.identityKind())
                .put(TokenExchangeConstants.CONTEXT_WORKLOAD_ID, authority.actingWorkload().getId().toString())
                .put(TokenExchangeConstants.CONTEXT_WORKLOAD_REF, authority.actingWorkload().getWorkloadRef())
                .put(TokenExchangeConstants.CONTEXT_ACTOR_CLIENT_ID, authority.actingWorkload().getOauthClientId())
                .build();
        OAuth2Token generated = tokenGenerator.generate(tokenContext);
        if (!(generated instanceof Jwt jwt)) {
            throw new OAuth2AuthenticationException(new OAuth2Error(OAuth2ErrorCodes.SERVER_ERROR));
        }

        OAuth2AccessToken accessToken = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER,
                jwt.getTokenValue(), jwt.getIssuedAt(), jwt.getExpiresAt(), exchange.requestedScopes());
        OAuth2Authorization authorization = OAuth2Authorization.from(pending)
                .token(accessToken, metadata -> metadata.put(OAuth2Authorization.Token.CLAIMS_METADATA_NAME, jwt.getClaims()))
                .build();
        authorizations.save(authorization);
        audit.logRequired(tenantId, actorClient.getClientId(), "TOKEN_EXCHANGE_SUCCEEDED", "delegated_token", authority.authorityId(),
                null, Map.of("subject", subject.getSubject(), "requester", actorClient.getClientId(),
                        "actor", authority.actingWorkload().getWorkloadRef(),
                        "profile", authority.profile().name().toLowerCase(),
                        "audience", exchange.audience(), "scopes", exchange.requestedScopes(),
                        "purpose", authority.purpose(), "expires_at", jwt.getExpiresAt()), authority.authorityId());

        Map<String, Object> responseParameters = new java.util.LinkedHashMap<>();
        responseParameters.put("issued_token_type", TokenExchangeConstants.ACCESS_TOKEN_TYPE);
        responseParameters.put("authority_id", authority.authorityId());
        if (authority.delegationId() != null) responseParameters.put("delegation_id", authority.delegationId());
        return new OAuth2AccessTokenAuthenticationToken(actorClient, actor, accessToken, null,
                responseParameters);
        } catch (OAuth2AuthenticationException denied) {
            String auditId = UUID.randomUUID().toString();
            audit.logRequired(actorAuthority.tenantId(), actorClient.getClientId(), "TOKEN_EXCHANGE_DENIED",
                    "delegated_token", auditId, null,
                    Map.of("actor", actorClient.getClientId(), "audience", exchange.audience(),
                            "reason", denied.getError().getErrorCode()), auditId);
            throw denied;
        }
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return TokenExchangeAuthenticationToken.class.isAssignableFrom(authentication);
    }

    private Jwt decodeSubject(String value) {
        try {
            Jwt jwt = subjectDecoder.decode(value);
            if (jwt.getSubject() == null || jwt.getSubject().isBlank()) fail(INVALID_GRANT);
            return jwt;
        } catch (JwtException | IllegalArgumentException ex) {
            throw new OAuth2AuthenticationException(INVALID_GRANT);
        }
    }

    private static OAuth2ClientAuthenticationToken authenticatedClient(Object principal) {
        if (!(principal instanceof OAuth2ClientAuthenticationToken)) fail(INVALID_CLIENT);
        OAuth2ClientAuthenticationToken client = (OAuth2ClientAuthenticationToken) principal;
        if (!client.isAuthenticated()) fail(INVALID_CLIENT);
        return client;
    }

    private static String requiredClaim(Jwt jwt, String name) {
        String value = jwt.getClaimAsString(name);
        if (value == null || value.isBlank()) fail(INVALID_GRANT);
        return value;
    }

    private static Set<String> subjectScopes(Jwt jwt) {
        Object raw = jwt.getClaims().get("scope");
        Set<String> result = new LinkedHashSet<>();
        if (raw instanceof String value) {
            for (String scope : value.trim().split("\\s+")) if (!scope.isBlank()) result.add(scope);
        } else if (raw instanceof Collection<?> values) {
            values.forEach(value -> result.add(String.valueOf(value)));
        }
        return result;
    }

    private static Duration minimum(Duration first, Duration second) {
        return first.compareTo(second) <= 0 ? first : second;
    }

    private static void fail(OAuth2Error error) { throw new OAuth2AuthenticationException(error); }
}
