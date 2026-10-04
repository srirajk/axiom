package com.openwolf.iam.auth;

import com.openwolf.iam.service.IamSessionService;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenIntrospection;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2TokenIntrospectionAuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2TokenIntrospectionAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;

import java.time.Instant;
import java.util.UUID;

/** Applies the durable session boundary to RFC 7662 introspection results. */
public final class SessionAwareIntrospectionAuthenticationProvider implements AuthenticationProvider {
    private final AuthenticationProvider delegate;
    private final OAuth2AuthorizationService authorizations;
    private final IamSessionService sessions;
    private final JwtDecoder localDecoder;

    public SessionAwareIntrospectionAuthenticationProvider(RegisteredClientRepository clients,
                                                           OAuth2AuthorizationService authorizations,
                                                           IamSessionService sessions, JwtDecoder localDecoder) {
        this(new OAuth2TokenIntrospectionAuthenticationProvider(clients, authorizations), authorizations, sessions, localDecoder);
    }

    SessionAwareIntrospectionAuthenticationProvider(AuthenticationProvider delegate,
                                                   OAuth2AuthorizationService authorizations,
                                                   IamSessionService sessions, JwtDecoder localDecoder) {
        this.delegate = delegate;
        this.authorizations = authorizations;
        this.sessions = sessions;
        this.localDecoder = localDecoder;
    }

    @Override
    public Authentication authenticate(Authentication authentication) {
        Authentication result = authenticateWithinIssuer(authentication);
        // Tenant disclosure boundary: a client may learn about tokens of its own tenant only. A token of another
        // tenant (or a caller that is not an active tenant client) is reported inactive, revealing nothing.
        if (result instanceof OAuth2TokenIntrospectionAuthenticationToken introspection
                && introspection.getTokenClaims() != null && introspection.getTokenClaims().isActive()) {
            var applicationService = applications.get();
            if (applicationService != null) {
                Object tokenTenant = introspection.getTokenClaims().getClaims().get("tenant_id");
                String callerTenant = applicationService.activeAuthority(callerClientId(introspection))
                        .map(com.openwolf.iam.service.TenantApplicationService.ClientAuthority::tenantId).orElse(null);
                if (callerTenant == null || !callerTenant.equals(tokenTenant)) return inactive(introspection);
            }
        }
        return result;
    }

    private Authentication authenticateWithinIssuer(Authentication authentication) {
        Authentication result = delegate.authenticate(authentication);
        if (!(result instanceof OAuth2TokenIntrospectionAuthenticationToken introspection)) return result;
        if (authorizations.findByToken(introspection.getToken(), OAuth2TokenType.ACCESS_TOKEN) == null) {
            return locallyIssued(introspection);
        }
        OAuth2TokenIntrospection claims = introspection.getTokenClaims();
        if (claims == null) return result;
        if (claims.getClaims().containsKey("delegation_id") || claims.getClaims().containsKey("act")) {
            return locallyIssued(introspection);
        }
        Object rawSession = claims.getClaims().get("sid");
        Object rawTenant = claims.getClaims().get("tenant_id");
        boolean active = false;
        if (rawSession instanceof String sid && rawTenant instanceof String tenant) {
            try {
                active = sessions.active(UUID.fromString(sid), tenant, Instant.now());
            } catch (IllegalArgumentException ignored) {
                active = false;
            }
        } else if (rawSession == null && rawTenant instanceof String tenant) {
            // A client-credentials token has no person and therefore no session; its status is the client's own
            // (active, confidential, same tenant) and, for a registered workload, the workload lifecycle — read live.
            active = sessionlessClientActive(claims.getClaims(), tenant);
        }
        if (!active) {
            return inactive(introspection);
        }
        OAuth2TokenIntrospection.Builder rebuilt = OAuth2TokenIntrospection.builder(true);
        claims.getClaims().forEach(rebuilt::claim);
        rebuilt.active(true);
        return new OAuth2TokenIntrospectionAuthenticationToken(introspection.getToken(),
                (org.springframework.security.core.Authentication) introspection.getPrincipal(), rebuilt.build());
    }

    private Authentication locallyIssued(OAuth2TokenIntrospectionAuthenticationToken introspection) {
        try {
            Jwt jwt = localDecoder.decode(introspection.getToken());
            String sid = jwt.getClaimAsString("sid");
            String tenant = jwt.getClaimAsString("tenant_id");
            if (sid == null || tenant == null || tenant.isBlank()
                    || jwt.getExpiresAt() == null || !jwt.getExpiresAt().isAfter(Instant.now())
                    || !sessions.active(UUID.fromString(sid), tenant, Instant.now())) {
                return inactive(introspection);
            }
            OAuth2TokenIntrospection.Builder rebuilt = OAuth2TokenIntrospection.builder(true);
            jwt.getClaims().forEach(rebuilt::claim);
            if (jwt.getClaims().containsKey(com.openwolf.iam.invocation.InvocationContextService.CLAIM_CONTEXT)) {
                // Context facts go only to the token's intended recipient; for anyone else the token is inactive.
                if (invocationContexts == null) return inactive(introspection);
                try {
                    rebuilt.claim("invocation_context", invocationContexts.project(jwt, callerClientId(introspection)));
                } catch (org.springframework.security.oauth2.core.OAuth2AuthenticationException denied) {
                    return inactive(introspection);
                }
            }
            rebuilt.tokenType("Bearer").active(true);
            return new OAuth2TokenIntrospectionAuthenticationToken(introspection.getToken(),
                    (org.springframework.security.core.Authentication) introspection.getPrincipal(), rebuilt.build());
        } catch (JwtException | IllegalArgumentException ex) {
            return inactive(introspection);
        }
    }

    private java.util.function.Supplier<com.openwolf.iam.service.TenantApplicationService> applications = () -> null;
    private java.util.function.Supplier<com.openwolf.iam.authority.lifecycle.WorkloadLifecycleService> workloads = () -> null;

    public void setClientStatus(java.util.function.Supplier<com.openwolf.iam.service.TenantApplicationService> applications,
                                java.util.function.Supplier<com.openwolf.iam.authority.lifecycle.WorkloadLifecycleService> workloads) {
        this.applications = applications;
        this.workloads = workloads;
    }

    private boolean sessionlessClientActive(java.util.Map<String, Object> claims, String tenant) {
        Object kind = claims.get("identity_kind");
        Object clientId = claims.get("client_id");
        if (!"workload".equals(kind) || claims.containsKey("act") || !(clientId instanceof String client)
                || !client.equals(claims.get("sub"))) return false;
        var applicationService = applications.get();
        if (applicationService == null) return false;
        boolean clientActive = applicationService.activeAuthority(client)
                .filter(a -> a.clientType() == com.openwolf.iam.entity.TenantApplicationClient.Type.CONFIDENTIAL_SERVICE)
                .filter(a -> a.tenantId().equals(tenant)).isPresent();
        var lifecycle = workloads.get();
        return clientActive && (lifecycle == null || lifecycle.clientMayIssue(client));
    }

    private com.openwolf.iam.invocation.InvocationContextService invocationContexts;

    public void setInvocationContexts(com.openwolf.iam.invocation.InvocationContextService invocationContexts) {
        this.invocationContexts = invocationContexts;
    }

    private static String callerClientId(OAuth2TokenIntrospectionAuthenticationToken introspection) {
        Object principal = introspection.getPrincipal();
        if (principal instanceof org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken client
                && client.getRegisteredClient() != null) return client.getRegisteredClient().getClientId();
        return "";
    }

    private Authentication inactive(OAuth2TokenIntrospectionAuthenticationToken introspection) {
        return new OAuth2TokenIntrospectionAuthenticationToken(introspection.getToken(),
                (org.springframework.security.core.Authentication) introspection.getPrincipal(), introspection.getTokenTypeHint(),
                java.util.Map.of("active", false));
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return OAuth2TokenIntrospectionAuthenticationToken.class.isAssignableFrom(authentication);
    }
}
