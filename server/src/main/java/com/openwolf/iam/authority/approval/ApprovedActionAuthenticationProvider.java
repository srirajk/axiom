package com.openwolf.iam.authority.approval;

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
 * Token endpoint for approved-action redemption (Phase 3.8): the named Agent workload, authenticating as itself,
 * presents the approval id and the exact action digest. Ordering, not cross-store atomicity: the consumption, the
 * token's Axiom session and the audit row are written in one PostgreSQL transaction that commits only after the token
 * is signed and its Redis record written. A Redis failure rolls the consumption back (approval stays CONFIRMED). A
 * PostgreSQL commit failure after the Redis write leaves an orphan Redis record (never returned to anyone; expires with
 * the token plus the store's grace) and an unconsumed approval; the orphan's session row was rolled back, so
 * introspection never accepts it (an offline, signature-only validator could, if it obtained the token from Redis). A
 * commit that succeeds but whose response is lost consumes the approval without the caller holding the token (a new
 * approval is then needed).
 */
public final class ApprovedActionAuthenticationProvider implements AuthorityGrantProvider {
    private final ActionApprovalService approvals;
    private final TenantApplicationService applications;
    private final AuthorityTokenIssuer issuer;
    private final AuditService audit;
    private final TransactionTemplate tx;
    private final Duration maximumTtl;

    public ApprovedActionAuthenticationProvider(ActionApprovalService approvals, TenantApplicationService applications,
                                                AuthorityTokenIssuer issuer, AuditService audit, TransactionTemplate tx,
                                                Duration maximumTtl) {
        if (maximumTtl.isNegative() || maximumTtl.isZero() || maximumTtl.compareTo(Duration.ofMinutes(10)) > 0) {
            throw new IllegalArgumentException("approved-action token TTL must be between one second and ten minutes");
        }
        this.approvals = approvals; this.applications = applications; this.issuer = issuer; this.audit = audit;
        this.tx = tx; this.maximumTtl = maximumTtl;
    }

    @Override public String grantType() { return ApprovedActionAuthenticationToken.GRANT_TYPE_VALUE; }

    @Override
    public AuthenticationConverter converter() {
        return request -> {
            if (!grantType().equals(request.getParameter("grant_type"))) return null;
            ExtensionGrantParameters.forbid(request, "subject_token", "actor_token", "refresh_token", "assertion", "code",
                    "purpose");
            UUID approval = ExtensionGrantParameters.uuid(request, "approval_id", true);
            String digest = ExtensionGrantParameters.required(request, "action_digest");
            if (!digest.matches("[0-9a-f]{64}")) ExtensionGrantParameters.invalid();
            return new ApprovedActionAuthenticationToken(SecurityContextHolder.getContext().getAuthentication(), approval,
                    digest, ExtensionGrantParameters.scopes(request));
        };
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return ApprovedActionAuthenticationToken.class.isAssignableFrom(authentication);
    }

    @Override
    public Authentication authenticate(Authentication authentication) {
        ApprovedActionAuthenticationToken request = (ApprovedActionAuthenticationToken) authentication;
        if (!(request.getPrincipal() instanceof OAuth2ClientAuthenticationToken client) || !client.isAuthenticated()
                || client.getRegisteredClient() == null) {
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_CLIENT);
        }
        String clientId = client.getRegisteredClient().getClientId();
        TenantApplicationService.ClientAuthority authority = applications.activeAuthority(clientId)
                .filter(a -> a.clientType() == TenantApplicationClient.Type.CONFIDENTIAL_SERVICE)
                .orElseThrow(() -> new OAuth2AuthenticationException(OAuth2ErrorCodes.UNAUTHORIZED_CLIENT));
        AuthorityTokenIssuer.Issued issued;
        try {
            issued = tx.execute(status -> {
                ActionApprovalService.Redemption redemption = approvals.redeem(clientId, request.approvalId(),
                        request.actionDigest(), request.requestedScopes());
                request.resolve(redemption);
                Duration ttl = Duration.between(Instant.now(), redemption.deadline());
                if (ttl.compareTo(maximumTtl) > 0) ttl = maximumTtl;
                AuthorityTokenIssuer.Issued token = issuer.issue(client, request,
                        ApprovedActionAuthenticationToken.GRANT_TYPE, redemption.initiator(), redemption.scopes(), ttl);
                Map<String, Object> details = new LinkedHashMap<>();
                details.put("token_id", token.jwt().getId());
                details.put("action_type", redemption.actionType());
                details.put("action_digest", redemption.actionDigest());
                details.put("approval_version", redemption.version());
                details.put("expires_at", token.jwt().getExpiresAt().toString());
                audit.logRequired(redemption.tenantId(), clientId, "ACTION_APPROVAL_CONSUMED", "action_approval",
                        redemption.approvalId().toString(), null, details, redemption.approvalId().toString());
                return token;
            });
        } catch (OAuth2AuthenticationException denied) {
            try {
                String id = UUID.randomUUID().toString();
                audit.logRequired(authority.tenantId(), clientId, "ACTION_APPROVAL_REDEMPTION_DENIED", "action_approval",
                        request.approvalId().toString(), null, Map.of("reason", denied.getError().getErrorCode()), id);
            } catch (RuntimeException ignored) {
                // The denial stands even if its audit cannot be written.
            }
            throw denied;
        } catch (RuntimeException unavailable) {
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.SERVER_ERROR);
        }
        return new OAuth2AccessTokenAuthenticationToken(client.getRegisteredClient(), client, issued.accessToken(), null,
                Map.of("approval_id", request.approvalId().toString()));
    }
}
