package com.openwolf.iam.auth;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.oidc.endpoint.OidcParameterNames;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.security.oauth2.jwt.Jwt;

import java.util.HashMap;
import java.util.Map;
import com.openwolf.iam.entity.TenantApplicationClient;
import com.openwolf.iam.service.ApplicationAccessService;
import com.openwolf.iam.service.TenantApplicationService;
import org.springframework.beans.factory.annotation.Autowired;
import java.time.Duration;
import java.time.Instant;
import com.openwolf.iam.service.IamSessionService;

/** Emits only Axiom identity and platform-entitlement claims. */
@Configuration
public class JwtClaimsCustomizer {

    private final OidcClaimEnricher enricher;
    private final TenantApplicationService applications;
    private final ApplicationAccessService applicationAccess;
    private final IamSessionService sessions;

    public JwtClaimsCustomizer(OidcClaimEnricher enricher) {
        this(enricher, null, null, null);
    }

    @Autowired
    public JwtClaimsCustomizer(OidcClaimEnricher enricher, TenantApplicationService applications,
                               ApplicationAccessService applicationAccess, IamSessionService sessions) {
        this.enricher = enricher; this.applications = applications; this.applicationAccess = applicationAccess; this.sessions = sessions;
    }

    public JwtClaimsCustomizer(OidcClaimEnricher enricher, TenantApplicationService applications,
                               ApplicationAccessService applicationAccess) {
        this(enricher, applications, applicationAccess, null);
    }

    @Bean
    public OAuth2TokenCustomizer<JwtEncodingContext> jwtTokenCustomizer() {
        return context -> {
            String subject = context.getPrincipal().getName();
            if (subject == null || subject.isBlank()) {
                throw new IllegalStateException("token subject is required");
            }
            if (OAuth2TokenType.ACCESS_TOKEN.getValue().equals(context.getTokenType().getValue())) {
                // RFC 9068 access-token profile. The Admin resource server deliberately rejects
                // generic JWTs, so tokens minted by this authorization server must carry the
                // matching media type as well as the Admin audience.
                context.getJwsHeader().type("at+jwt");
                String clientId = context.getRegisteredClient().getClientId();
                if (TokenExchangeConstants.GRANT_TYPE.equals(context.getAuthorizationGrantType())) {
                    TokenExchangeAuthenticationToken.AuthorityContext resolved =
                            context.getAuthorizationGrant() instanceof TokenExchangeAuthenticationToken exchange
                                    ? exchange.authorityContext() : null;
                    Jwt subjectJwt = resolved == null ? context.get(TokenExchangeConstants.CONTEXT_SUBJECT) : resolved.subject();
                    String audience = resolved == null ? context.get(TokenExchangeConstants.CONTEXT_AUDIENCE) : resolved.audience();
                    String purpose = resolved == null ? context.get(TokenExchangeConstants.CONTEXT_PURPOSE) : resolved.purpose();
                    String authorityProfile = resolved == null ? context.get(TokenExchangeConstants.CONTEXT_AUTHORITY_PROFILE) : resolved.authorityProfile();
                    String authorityId = resolved == null ? context.get(TokenExchangeConstants.CONTEXT_AUTHORITY_ID) : resolved.authorityId();
                    String delegationId = resolved == null ? context.get(TokenExchangeConstants.CONTEXT_DELEGATION_ID) : resolved.delegationId();
                    String tokenUse = resolved == null ? context.get(TokenExchangeConstants.CONTEXT_TOKEN_USE) : resolved.tokenUse();
                    String identityKind = resolved == null ? context.get(TokenExchangeConstants.CONTEXT_IDENTITY_KIND) : resolved.identityKind();
                    String workloadId = resolved == null ? context.get(TokenExchangeConstants.CONTEXT_WORKLOAD_ID) : resolved.workloadId();
                    String workloadRef = resolved == null ? context.get(TokenExchangeConstants.CONTEXT_WORKLOAD_REF) : resolved.workloadRef();
                    String actorClientId = resolved == null ? context.get(TokenExchangeConstants.CONTEXT_ACTOR_CLIENT_ID) : resolved.actorClientId();
                    if (subjectJwt == null || audience == null || purpose == null || authorityProfile == null
                            || authorityId == null || tokenUse == null || identityKind == null
                            || workloadId == null || workloadRef == null || actorClientId == null) {
                        throw new IllegalStateException("token exchange authority context is incomplete");
                    }
                    TenantApplicationService.ClientAuthority actorAuthority = applications.activeAuthority(clientId)
                            .filter(authority -> authority.clientType() == TenantApplicationClient.Type.CONFIDENTIAL_SERVICE)
                            .orElseThrow(() -> new IllegalStateException("token exchange actor is disabled or unknown"));
                    String tenantId = TenantClaims.requireTenant(subjectJwt.getClaimAsString("tenant_id"));
                    if (!actorAuthority.tenantId().equals(tenantId)) {
                        throw new IllegalStateException("token exchange authority changed during issuance");
                    }
                    context.getClaims().subject(subjectJwt.getSubject());
                    context.getClaims().audience(java.util.List.of(audience));
                    context.getClaims().claim("tenant_id", tenantId);
                    context.getClaims().claim("identity_kind", identityKind);
                    context.getClaims().claim("client_id", clientId);
                    context.getClaims().claim("azp", clientId);
                    context.getClaims().claim("act", Map.of("sub", workloadRef, "client_id", actorClientId,
                            "workload_id", workloadId));
                    context.getClaims().claim("purpose", purpose);
                    context.getClaims().claim("authority_profile", authorityProfile);
                    context.getClaims().claim("authority_id", authorityId);
                    context.getClaims().claim("token_use", tokenUse);
                    if (delegationId != null) context.getClaims().claim("delegation_id", delegationId);
                    String rootSession = subjectJwt.getClaimAsString("subject_sid");
                    if (rootSession == null || rootSession.isBlank()) rootSession = subjectJwt.getClaimAsString("sid");
                    if (rootSession != null && !rootSession.isBlank()) {
                        context.getClaims().claim("subject_sid", rootSession);
                    }
                    addSession(context, tenantId, actorAuthority.applicationId(), clientId, subjectJwt.getSubject(), true);
                    return;
                }
                Map<String, Object> enriched;
                var applicationAuthority = applications == null ? java.util.Optional.<TenantApplicationService.ClientAuthority>empty()
                        : applications.activeAuthority(clientId);
                if (applicationAuthority.isPresent()) {
                    TenantApplicationService.ClientAuthority authority = applicationAuthority.get();
                    if (AuthorizationGrantType.CLIENT_CREDENTIALS.equals(context.getAuthorizationGrantType())) {
                        if (authority.clientType() != TenantApplicationClient.Type.CONFIDENTIAL_SERVICE) {
                            throw new IllegalStateException("public application client cannot use client credentials");
                        }
                        enriched = Map.of("tenant_id", TenantClaims.requireTenant(authority.tenantId()),
                                "identity_kind", "workload");
                    } else {
                        if (authority.clientType() != TenantApplicationClient.Type.PUBLIC_BROWSER) {
                            throw new IllegalStateException("service application client cannot mint a human token");
                        }
                        if (applicationAccess == null) {
                            throw new IllegalStateException("application access authority is unavailable");
                        }
                        Map<String, Object> humanClaims;
                        try {
                            humanClaims = new HashMap<>(applicationAccess.tokenClaims(clientId, subject));
                            applications.requireHumanClientTenant(clientId,
                                    TenantClaims.requireTenant(String.valueOf(humanClaims.get("tenant_id"))));
                        } catch (IllegalStateException denied) {
                            throw new OAuth2AuthenticationException(new OAuth2Error(OAuth2ErrorCodes.INVALID_GRANT));
                        }
                        humanClaims.putAll(enricher.enrichIdToken(subject));
                        humanClaims.put("identity_kind", "workforce");
                        enriched = humanClaims;
                    }
                    TenantClaims.requireTenant(String.valueOf(enriched.get("tenant_id")));
                    enriched.forEach((key, value) -> context.getClaims().claim(key, value));
                    context.getClaims().claim("client_id", clientId);
                    context.getClaims().audience(java.util.List.of(authority.audience()));
                    addSession(context, authority.tenantId(), authority.applicationId(), clientId, subject, true);
                    return;
                }
                if (applications != null && applications.knownButDisabled(clientId)) {
                    throw new IllegalStateException("application client is disabled");
                }
                if (AuthorizationGrantType.CLIENT_CREDENTIALS.equals(context.getAuthorizationGrantType())) {
                    throw new IllegalStateException("service client is not registered to an active application");
                } else {
                    enriched = new HashMap<>(enricher.enrich(subject));
                    enriched.putAll(enricher.enrichIdToken(subject));
                    enriched.put("identity_kind", "workforce");
                }
                TenantClaims.requireTenant(String.valueOf(enriched.get("tenant_id")));
                enriched.forEach((key, value) -> context.getClaims().claim(key, value));
                // Bind every access token to the exact OAuth client that obtained it.  The
                context.getClaims().claim("client_id", clientId);
                context.getClaims().audience(java.util.List.of(AxiomApiJwtValidator.AUDIENCE));
                addSession(context, String.valueOf(enriched.get("tenant_id")), null, clientId, subject, true);
            } else if (OidcParameterNames.ID_TOKEN.equals(context.getTokenType().getValue())) {
                enricher.enrichIdToken(subject).forEach((key, value) -> context.getClaims().claim(key, value));
                String clientId = context.getRegisteredClient().getClientId();
                var authority = applications == null ? java.util.Optional.<TenantApplicationService.ClientAuthority>empty()
                        : applications.activeAuthority(clientId);
                String tenantId = authority.map(TenantApplicationService.ClientAuthority::tenantId)
                        .orElseGet(() -> String.valueOf(enricher.enrich(subject).get("tenant_id")));
                addSession(context, tenantId,
                        authority.map(TenantApplicationService.ClientAuthority::applicationId).orElse(null),
                        clientId, subject, false);
            }
        };
    }

    private void addSession(JwtEncodingContext context, String tenantId, java.util.UUID applicationId,
                            String clientId, String principalId, boolean exposeAxiomSessionId) {
        if (sessions == null || context.getAuthorization() == null) return;
        Duration ttl = context.getRegisteredClient().getTokenSettings().getAccessTokenTimeToLive();
        Instant expiry = Instant.now().plus(ttl);
        java.util.UUID sessionId = sessions.issue(context.getAuthorization().getId(), tenantId, principalId,
                applicationId, clientId, expiry);
        // Access tokens use Axiom's durable UUID session id for resource-server revocation checks.
        // ID-token `sid` is owned by Spring Authorization Server's OIDC logout contract and must
        // remain the framework-generated value used to locate the OAuth authorization.
        if (exposeAxiomSessionId) {
            context.getClaims().claim("sid", sessionId.toString());
        }
    }
}
