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
                if (context.getAuthorizationGrant() instanceof ServerResolvedClaims resolvedGrant) {
                    // Phase 3 grants: every claim was resolved from durable state by the grant's provider.
                    context.getClaims().subject(resolvedGrant.subject());
                    context.getClaims().audience(resolvedGrant.audience());
                    resolvedGrant.claims().forEach((key, value) -> context.getClaims().claim(key, value));
                    context.getClaims().claim("client_id", clientId);
                    context.getClaims().claim("azp", clientId);
                    addSession(context, resolvedGrant.sessionTenantId(), resolvedGrant.sessionApplicationId(), clientId,
                            resolvedGrant.subject(), true, resolvedGrant.workforceSession());
                    return;
                }
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
                    if (resolved != null && resolved.invocation() != null) {
                        context.getClaims().claim("ctx", resolved.invocation().contextId());
                        context.getClaims().claim("ctx_ver", resolved.invocation().version());
                        context.getClaims().claim("ctx_depth", resolved.invocation().depth());
                    }
                    // Phase 3.9: verified assurance is preserved through exchange, never created or upgraded by it.
                    AuthenticationAssurance.propagate(subjectJwt, (key, value) -> context.getClaims().claim(key, value));
                    String rootSession = subjectJwt.getClaimAsString("subject_sid");
                    if (rootSession == null || rootSession.isBlank()) rootSession = subjectJwt.getClaimAsString("sid");
                    if (rootSession != null && !rootSession.isBlank()) {
                        context.getClaims().claim("subject_sid", rootSession);
                    }
                    addSession(context, tenantId, actorAuthority.applicationId(), clientId, subjectJwt.getSubject(),
                            true, "workforce".equals(identityKind));
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
                        // Phase 3.15: a suspended, retired or revoked (or unowned) Agent workload gets no new token.
                        if (workloadLifecycle != null && !workloadLifecycle.clientMayIssue(clientId)) {
                            throw new OAuth2AuthenticationException(new OAuth2Error(OAuth2ErrorCodes.UNAUTHORIZED_CLIENT));
                        }
                        enriched = Map.of("tenant_id", TenantClaims.requireTenant(authority.tenantId()),
                                "identity_kind", "workload");
                        // Workload tokens are short-lived (default five minutes) regardless of the client's
                        // registered access-token lifetime; the client simply asks again.
                        context.getClaims().claims(all -> {
                            if (all.get("iat") instanceof Instant issued && all.get("exp") instanceof Instant expiry
                                    && expiry.isAfter(issued.plus(clientCredentialsTtl))) {
                                all.put("exp", issued.plus(clientCredentialsTtl));
                            }
                        });
                    } else if (authority.customerSignIn()) {
                        // CIAM browser login: only a customer login of this client's tenant, still ACTIVE at the same
                        // token version (no suspension or credential recovery since sign-in; re-checked on refresh).
                        enriched = customerClaims(context, authority);
                    } else {
                        if (!authority.clientType().interactive()) {
                            throw new IllegalStateException("service application client cannot mint a human token");
                        }
                        if (context.getPrincipal() instanceof CustomerAuthenticationToken) {
                            throw new OAuth2AuthenticationException(new OAuth2Error(OAuth2ErrorCodes.INVALID_GRANT));
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
                        // IDP-04: a business scope is issued only where the person holds the matching application
                        // permission now (re-evaluated at every issuance, including refresh); OIDC scopes pass through.
                        narrowToEntitlement(context, humanClaims.get("permissions"));
                    }
                    TenantClaims.requireTenant(String.valueOf(enriched.get("tenant_id")));
                    enriched.forEach((key, value) -> context.getClaims().claim(key, value));
                    addAssurance(context);
                    context.getClaims().claim("client_id", clientId);
                    context.getClaims().audience(java.util.List.of(authority.audience()));
                    addSession(context, authority.tenantId(), authority.applicationId(), clientId, subject, true,
                            !AuthorizationGrantType.CLIENT_CREDENTIALS.equals(context.getAuthorizationGrantType())
                                    && !authority.customerSignIn());
                    return;
                }
                if (context.getPrincipal() instanceof CustomerAuthenticationToken) {
                    // Customers sign in only through customer-facing tenant clients, never the Axiom admin client.
                    throw new OAuth2AuthenticationException(new OAuth2Error(OAuth2ErrorCodes.INVALID_GRANT));
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
                addAssurance(context);
                // Bind every access token to the exact OAuth client that obtained it.  The
                context.getClaims().claim("client_id", clientId);
                context.getClaims().audience(java.util.List.of(AxiomApiJwtValidator.AUDIENCE));
                addSession(context, String.valueOf(enriched.get("tenant_id")), null, clientId, subject, true, true);
            } else if (OidcParameterNames.ID_TOKEN.equals(context.getTokenType().getValue())) {
                String clientId = context.getRegisteredClient().getClientId();
                var authority = applications == null ? java.util.Optional.<TenantApplicationService.ClientAuthority>empty()
                        : applications.activeAuthority(clientId);
                if (context.getPrincipal() instanceof CustomerAuthenticationToken) {
                    TenantApplicationService.ClientAuthority customerClient = authority
                            .filter(TenantApplicationService.ClientAuthority::customerSignIn)
                            .orElseThrow(() -> new OAuth2AuthenticationException(new OAuth2Error(OAuth2ErrorCodes.INVALID_GRANT)));
                    var customer = currentCustomer(context, customerClient);
                    if (context.getAuthorizedScopes().contains("email")) {
                        context.getClaims().claim("email", customer.email());
                        context.getClaims().claim("email_verified", true);
                    }
                    if (context.getAuthorizedScopes().contains("profile")) context.getClaims().claim("name", customer.displayName());
                    addAssurance(context);
                    addSession(context, customerClient.tenantId(), customerClient.applicationId(), clientId, subject, false, false);
                    return;
                }
                enricher.enrichIdToken(subject).forEach((key, value) -> context.getClaims().claim(key, value));
                String tenantId = authority.map(TenantApplicationService.ClientAuthority::tenantId)
                        .orElseGet(() -> String.valueOf(enricher.enrich(subject).get("tenant_id")));
                addSession(context, tenantId,
                        authority.map(TenantApplicationService.ClientAuthority::applicationId).orElse(null),
                        clientId, subject, false, true);
            }
        };
    }

    /** Phase 3.9: assurance recorded by an interactive browser login (absent for every other principal). */
    private static void addAssurance(JwtEncodingContext context) {
        if (AuthorizationGrantType.CLIENT_CREDENTIALS.equals(context.getAuthorizationGrantType())) return;
        if (context.getPrincipal().getDetails() instanceof AssuranceAuthenticationDetails details
                && details.authenticatedAt() != null && details.acr() != null) {
            context.getClaims().claim(AuthenticationAssurance.CLAIM_AUTH_TIME, details.authenticatedAt().getEpochSecond());
            context.getClaims().claim(AuthenticationAssurance.CLAIM_ACR, details.acr());
            context.getClaims().claim(AuthenticationAssurance.CLAIM_AMR, java.util.List.of("pwd"));
        }
    }

    private Duration clientCredentialsTtl = Duration.ofMinutes(5);

    @Autowired(required = false)
    void setClientCredentialsTtl(@org.springframework.beans.factory.annotation.Value(
            "${iam.oauth2.client-credentials.ttl:PT5M}") Duration ttl) {
        if (ttl.isNegative() || ttl.isZero() || ttl.compareTo(Duration.ofHours(1)) > 0) {
            throw new IllegalArgumentException("client-credentials token TTL must be between one second and one hour");
        }
        this.clientCredentialsTtl = ttl;
    }

    private com.openwolf.iam.authority.lifecycle.WorkloadLifecycleService workloadLifecycle;

    @Autowired(required = false)
    void setWorkloadLifecycle(@org.springframework.context.annotation.Lazy
                              com.openwolf.iam.authority.lifecycle.WorkloadLifecycleService workloadLifecycle) {
        this.workloadLifecycle = workloadLifecycle;
    }

    private BusinessScopeRegistry businessScopes;

    @Autowired(required = false)
    void setBusinessScopes(BusinessScopeRegistry businessScopes) {
        this.businessScopes = businessScopes;
    }

    private void narrowToEntitlement(JwtEncodingContext context, Object permissions) {
        java.util.Set<String> held = new java.util.HashSet<>();
        if (permissions instanceof java.util.Collection<?> values) values.forEach(value -> held.add(String.valueOf(value)));
        context.getClaims().claims(all -> {
            Object raw = all.get("scope");
            java.util.List<String> scopes = new java.util.ArrayList<>();
            if (raw instanceof String text) {
                for (String scope : text.trim().split("\\s+")) if (!scope.isBlank()) scopes.add(scope);
            } else if (raw instanceof java.util.Collection<?> values) {
                values.forEach(value -> scopes.add(String.valueOf(value)));
            } else {
                return;
            }
            java.util.List<String> issued = scopes.stream()
                    .filter(scope -> businessScopes == null || !businessScopes.isApproved(scope) || held.contains(scope))
                    .toList();
            if (issued.size() == scopes.size()) return;
            all.put("scope", raw instanceof String ? String.join(" ", issued) : new java.util.LinkedHashSet<>(issued));
        });
    }

    private com.openwolf.iam.service.CiamCustomerAuthenticationService customers;

    @Autowired(required = false)
    void setCustomers(@org.springframework.context.annotation.Lazy
                      com.openwolf.iam.service.CiamCustomerAuthenticationService customers) {
        this.customers = customers;
    }

    private com.openwolf.iam.service.CiamCustomerAuthenticationService.AuthenticatedCustomer currentCustomer(
            JwtEncodingContext context, TenantApplicationService.ClientAuthority client) {
        if (!(context.getPrincipal() instanceof CustomerAuthenticationToken customer) || customers == null
                || !customer.tenantId().equals(client.tenantId())) {
            throw new OAuth2AuthenticationException(new OAuth2Error(OAuth2ErrorCodes.INVALID_GRANT));
        }
        try {
            return customers.current(customer.tenantId(), java.util.UUID.fromString(customer.getName()),
                            customer.tokenVersion())
                    .orElseThrow(() -> new OAuth2AuthenticationException(new OAuth2Error(OAuth2ErrorCodes.INVALID_GRANT)));
        } catch (IllegalArgumentException malformed) {
            throw new OAuth2AuthenticationException(new OAuth2Error(OAuth2ErrorCodes.INVALID_GRANT));
        }
    }

    /** Access-token claims of a customer browser login: the customer, never workforce roles or entitlements. */
    private Map<String, Object> customerClaims(JwtEncodingContext context, TenantApplicationService.ClientAuthority client) {
        var customer = currentCustomer(context, client);
        Map<String, Object> claims = new HashMap<>();
        claims.put("tenant_id", TenantClaims.requireTenant(client.tenantId()));
        claims.put("identity_kind", "customer");
        claims.put("token_version", customer.tokenVersion());
        return claims;
    }

    private void addSession(JwtEncodingContext context, String tenantId, java.util.UUID applicationId,
                            String clientId, String principalId, boolean exposeAxiomSessionId, boolean workforce) {
        if (sessions == null || context.getAuthorization() == null) return;
        Duration ttl = context.getRegisteredClient().getTokenSettings().getAccessTokenTimeToLive();
        // A login that may be renewed by refresh token keeps one durable session for the whole refresh family: the
        // session (and with it every token of the family) ends at the refresh-token lifetime counted from sign-in, or
        // earlier on logout, revocation, consent withdrawal or disable. Refresh never extends it.
        if (context.getRegisteredClient().getAuthorizationGrantTypes().contains(AuthorizationGrantType.REFRESH_TOKEN)
                && OfflineAccess.granted(context)) {
            Duration refresh = context.getRegisteredClient().getTokenSettings().getRefreshTokenTimeToLive();
            if (refresh.compareTo(ttl) > 0) ttl = refresh;
        }
        Instant expiry = Instant.now().plus(ttl);
        java.util.UUID sessionId;
        try {
            sessionId = workforce
                    ? sessions.issueForWorkforce(context.getAuthorization().getId(), tenantId, principalId,
                            applicationId, clientId, expiry)
                    : sessions.issue(context.getAuthorization().getId(), tenantId, principalId,
                            applicationId, clientId, expiry);
        } catch (IllegalStateException | org.springframework.security.authentication.DisabledException ended) {
            // The login's durable session ended (logout, revocation, expiry) or the person was disabled: nothing more
            // is issued from it, including by refresh.
            throw new OAuth2AuthenticationException(new OAuth2Error(OAuth2ErrorCodes.INVALID_GRANT));
        }
        // Access tokens use Axiom's durable UUID session id for resource-server revocation checks.
        // ID-token `sid` is owned by Spring Authorization Server's OIDC logout contract and must
        // remain the framework-generated value used to locate the OAuth authorization.
        if (exposeAxiomSessionId) {
            context.getClaims().claim("sid", sessionId.toString());
        }
    }
}
