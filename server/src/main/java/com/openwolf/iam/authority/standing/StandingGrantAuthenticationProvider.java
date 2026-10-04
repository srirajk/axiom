package com.openwolf.iam.authority.standing;

import com.openwolf.iam.auth.AuthorityGrantProvider;
import com.openwolf.iam.authority.AuthorityTokenIssuer;
import com.openwolf.iam.authority.ExtensionGrantParameters;
import com.openwolf.iam.entity.TenantApplicationClient;
import com.openwolf.iam.service.AuditService;
import com.openwolf.iam.service.TenantApplicationService;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AccessTokenAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.transaction.support.TransactionTemplate;

import java.time.Duration;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;

/**
 * Token endpoint for standing-grant redemption (Phase 3.3): the bound workload authenticates as itself and presents
 * the grant id plus its current renewal handle (none on the first claim). Nothing else is accepted as renewal input —
 * in particular no access token, so an expired or stolen access token can never renew itself. Ordering, not
 * cross-store atomicity: the handle rotation commits in PostgreSQL only after the token is signed and its Redis record
 * written, so a Redis failure leaves the old handle valid. A PostgreSQL commit failure after the Redis write leaves an
 * orphan Redis record (never returned; expires with the token plus the store's grace) and the old handle valid; the
 * orphan's Axiom session row was rolled back, so introspection never accepts it (an offline, signature-only validator
 * could, if it obtained the token from Redis). A commit whose response is lost
 * rotates the handle without the caller seeing it; the next renewal then presents the superseded handle and the grant
 * is withdrawn (fail closed; the owner must approve again).
 */
public final class StandingGrantAuthenticationProvider implements AuthorityGrantProvider {
    private final StandingGrantService grants;
    private final StandingGrantService.TaskBinding tasks;
    private final TenantApplicationService applications;
    private final AuthorityTokenIssuer issuer;
    private final AuditService audit;
    private final TransactionTemplate tx;
    private final Duration maximumTtl;

    public StandingGrantAuthenticationProvider(StandingGrantService grants, StandingGrantService.TaskBinding tasks,
                                               TenantApplicationService applications, AuthorityTokenIssuer issuer,
                                               AuditService audit, TransactionTemplate tx, Duration maximumTtl) {
        if (maximumTtl.isNegative() || maximumTtl.isZero() || maximumTtl.compareTo(Duration.ofMinutes(10)) > 0) {
            throw new IllegalArgumentException("standing-grant token TTL must be between one second and ten minutes");
        }
        this.grants = grants; this.tasks = tasks; this.applications = applications; this.issuer = issuer;
        this.audit = audit; this.tx = tx; this.maximumTtl = maximumTtl;
    }

    @Override public String grantType() { return StandingGrantAuthenticationToken.GRANT_TYPE_VALUE; }

    @Override
    public AuthenticationConverter converter() {
        return request -> {
            if (!grantType().equals(request.getParameter("grant_type"))) return null;
            ExtensionGrantParameters.forbid(request, "subject_token", "actor_token", "refresh_token", "assertion", "code");
            UUID grant = ExtensionGrantParameters.uuid(request, "standing_grant", true);
            String handle = ExtensionGrantParameters.optional(request, "renewal_handle");
            if (handle != null && !handle.matches("[A-Za-z0-9_-]{16,128}")) ExtensionGrantParameters.invalid();
            UUID task = ExtensionGrantParameters.uuid(request, "task_id", false);
            return new StandingGrantAuthenticationToken(SecurityContextHolder.getContext().getAuthentication(), grant,
                    handle, ExtensionGrantParameters.scopes(request), task);
        };
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return StandingGrantAuthenticationToken.class.isAssignableFrom(authentication);
    }

    private record Outcome(AuthorityTokenIssuer.Issued issued, StandingGrantService.Redemption redemption,
                           boolean reuse) {}

    @Override
    public Authentication authenticate(Authentication authentication) {
        StandingGrantAuthenticationToken request = (StandingGrantAuthenticationToken) authentication;
        if (!(request.getPrincipal() instanceof OAuth2ClientAuthenticationToken client) || !client.isAuthenticated()
                || client.getRegisteredClient() == null) {
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_CLIENT);
        }
        String clientId = client.getRegisteredClient().getClientId();
        TenantApplicationService.ClientAuthority authority = applications.activeAuthority(clientId)
                .filter(a -> a.clientType() == TenantApplicationClient.Type.CONFIDENTIAL_SERVICE)
                .orElseThrow(() -> new OAuth2AuthenticationException(OAuth2ErrorCodes.UNAUTHORIZED_CLIENT));
        Outcome outcome;
        try {
            outcome = tx.execute(status -> {
                StandingGrantService.Redemption redemption;
                try {
                    redemption = grants.redeem(clientId, request.grantId(), request.renewalHandle(),
                            request.requestedScopes(), request.taskId(), tasks);
                } catch (StandingGrantService.ReuseDetected reuse) {
                    return new Outcome(null, null, true);  // commit the revocation, then deny
                }
                request.resolve(redemption);
                Duration ttl = Duration.between(Instant.now(), redemption.expiresAt());
                if (ttl.compareTo(maximumTtl) > 0) ttl = maximumTtl;
                AuthorityTokenIssuer.Issued issued = issuer.issue(client, request,
                        StandingGrantAuthenticationToken.GRANT_TYPE, redemption.owner(), redemption.scopes(), ttl);
                Map<String, Object> details = new LinkedHashMap<>();
                details.put("token_id", issued.jwt().getId());
                details.put("grant_version", redemption.version());
                details.put("handle_generation", redemption.generation());
                details.put("scopes", redemption.scopes());
                details.put("expires_at", issued.jwt().getExpiresAt().toString());
                if (redemption.taskId() != null) details.put("task_id", redemption.taskId().toString());
                audit.logRequired(redemption.tenantId(), clientId, "STANDING_GRANT_REDEEMED", "standing_grant",
                        redemption.grantId().toString(), null, details, redemption.grantId().toString());
                return new Outcome(issued, redemption, false);
            });
        } catch (OAuth2AuthenticationException denied) {
            deniedAudit(authority.tenantId(), clientId, request, denied.getError().getErrorCode());
            throw denied;
        } catch (RuntimeException unavailable) {
            // Database, Redis or signing failure: nothing committed, the presented handle stays valid.
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.SERVER_ERROR);
        }
        if (outcome == null || outcome.reuse()) {
            deniedAudit(authority.tenantId(), clientId, request, "renewal_handle_reuse");
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_GRANT);
        }
        Map<String, Object> parameters = new LinkedHashMap<>();
        parameters.put("standing_grant", outcome.redemption().grantId().toString());
        parameters.put("renewal_handle", outcome.redemption().renewalHandle());
        return new OAuth2AccessTokenAuthenticationToken(client.getRegisteredClient(), client,
                outcome.issued().accessToken(), null, parameters);
    }

    private void deniedAudit(String tenantId, String clientId, StandingGrantAuthenticationToken request, String reason) {
        try {
            String id = UUID.randomUUID().toString();
            audit.logRequired(tenantId, clientId, "STANDING_GRANT_REDEMPTION_DENIED", "standing_grant",
                    request.grantId().toString(), null, Map.of("reason", reason), id);
        } catch (RuntimeException ignored) {
            // The denial stands even if its audit cannot be written (e.g. database outage).
        }
    }
}
