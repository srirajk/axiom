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
                Map<String, Object> enriched;
                var applicationAuthority = applications == null ? java.util.Optional.<TenantApplicationService.ClientAuthority>empty()
                        : applications.activeAuthority(clientId);
                if (applicationAuthority.isPresent()) {
                    TenantApplicationService.ClientAuthority authority = applicationAuthority.get();
                    if (AuthorizationGrantType.CLIENT_CREDENTIALS.equals(context.getAuthorizationGrantType())) {
                        if (authority.clientType() != TenantApplicationClient.Type.CONFIDENTIAL_SERVICE) {
                            throw new IllegalStateException("public application client cannot use client credentials");
                        }
                        enriched = Map.of("tenant_id", TenantClaims.requireTenant(authority.tenantId()));
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
