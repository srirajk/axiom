package com.openwolf.iam.authority.standing;

import com.openwolf.iam.auth.ServerResolvedClaims;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationGrantAuthenticationToken;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

/** Standing-grant redemption request (Phase 3.3); claims are bound only after the grant is resolved. */
public final class StandingGrantAuthenticationToken extends OAuth2AuthorizationGrantAuthenticationToken
        implements ServerResolvedClaims {
    public static final String GRANT_TYPE_VALUE = "urn:openwolf:params:oauth:grant-type:standing-grant";
    public static final AuthorizationGrantType GRANT_TYPE = new AuthorizationGrantType(GRANT_TYPE_VALUE);

    private final UUID grantId;
    private final transient String renewalHandle;
    private final Set<String> requestedScopes;
    private final UUID taskId;
    private StandingGrantService.Redemption resolved;

    StandingGrantAuthenticationToken(Authentication client, UUID grantId, String renewalHandle,
                                     Set<String> requestedScopes, UUID taskId) {
        super(GRANT_TYPE, client, Map.of());
        this.grantId = grantId;
        this.renewalHandle = renewalHandle;
        this.requestedScopes = Set.copyOf(requestedScopes);
        this.taskId = taskId;
    }

    UUID grantId() { return grantId; }
    String renewalHandle() { return renewalHandle; }
    Set<String> requestedScopes() { return requestedScopes; }
    UUID taskId() { return taskId; }

    void resolve(StandingGrantService.Redemption redemption) {
        if (resolved != null) throw new IllegalStateException("standing grant already resolved");
        resolved = redemption;
    }

    private StandingGrantService.Redemption resolved() {
        if (resolved == null) throw new IllegalStateException("standing grant is not resolved");
        return resolved;
    }

    @Override public String subject() { return resolved().owner(); }
    @Override public List<String> audience() { return List.of(resolved().audience()); }
    @Override public String sessionTenantId() { return resolved().tenantId(); }
    @Override public UUID sessionApplicationId() { return resolved().ownerApplicationId(); }
    @Override public boolean workforceSession() { return true; }

    @Override
    public Map<String, Object> claims() {
        StandingGrantService.Redemption r = resolved();
        Map<String, Object> claims = new LinkedHashMap<>();
        claims.put("tenant_id", r.tenantId());
        claims.put("identity_kind", "workforce");
        claims.put("act", Map.of("sub", r.workloadRef(), "client_id", r.actorClientId(), "workload_id", r.workloadId()));
        claims.put("token_use", "delegated_access");
        claims.put("authority_profile", StandingGrantService.PROFILE);
        claims.put("authority_id", r.grantId().toString());
        claims.put(StandingGrantService.CLAIM_GRANT, r.grantId().toString());
        claims.put(StandingGrantService.CLAIM_VERSION, r.version());
        if (r.taskId() != null) claims.put(StandingGrantService.CLAIM_TASK, r.taskId().toString());
        return claims;
    }
}
