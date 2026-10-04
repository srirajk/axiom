package com.openwolf.iam.authority.approval;

import com.openwolf.iam.auth.AuthenticationAssurance;
import com.openwolf.iam.auth.ServerResolvedClaims;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationGrantAuthenticationToken;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

/** Approved-action redemption request (Phase 3.8); claims are bound only after single-use consumption. */
public final class ApprovedActionAuthenticationToken extends OAuth2AuthorizationGrantAuthenticationToken
        implements ServerResolvedClaims {
    public static final String GRANT_TYPE_VALUE = "urn:openwolf:params:oauth:grant-type:approved-action";
    public static final AuthorizationGrantType GRANT_TYPE = new AuthorizationGrantType(GRANT_TYPE_VALUE);

    private final UUID approvalId;
    private final String actionDigest;
    private final Set<String> requestedScopes;
    private ActionApprovalService.Redemption resolved;

    ApprovedActionAuthenticationToken(Authentication client, UUID approvalId, String actionDigest, Set<String> scopes) {
        super(GRANT_TYPE, client, Map.of());
        this.approvalId = approvalId;
        this.actionDigest = actionDigest;
        this.requestedScopes = Set.copyOf(scopes);
    }

    UUID approvalId() { return approvalId; }
    String actionDigest() { return actionDigest; }
    Set<String> requestedScopes() { return requestedScopes; }

    void resolve(ActionApprovalService.Redemption redemption) {
        if (resolved != null) throw new IllegalStateException("approval already resolved");
        resolved = redemption;
    }

    private ActionApprovalService.Redemption r() {
        if (resolved == null) throw new IllegalStateException("approval is not resolved");
        return resolved;
    }

    @Override public String subject() { return r().initiator(); }
    @Override public List<String> audience() { return List.of(r().audience()); }
    @Override public String sessionTenantId() { return r().tenantId(); }
    @Override public UUID sessionApplicationId() { return r().ownerApplicationId(); }
    @Override public boolean workforceSession() { return true; }

    @Override
    public Map<String, Object> claims() {
        ActionApprovalService.Redemption r = r();
        Map<String, Object> claims = new LinkedHashMap<>();
        claims.put("tenant_id", r.tenantId());
        claims.put("identity_kind", "workforce");
        claims.put("act", Map.of("sub", r.workloadRef(), "client_id", r.actorClientId(), "workload_id", r.workloadId()));
        claims.put("token_use", ActionApprovalService.PROFILE);
        claims.put("authority_profile", ActionApprovalService.PROFILE);
        claims.put("authority_id", r.approvalId().toString());
        claims.put("approval_id", r.approvalId().toString());
        claims.put("ap_ver", r.version());
        claims.put("action_type", r.actionType());
        claims.put("action_digest", r.actionDigest());
        // Verified assurance of the initiator's step-up confirmation, preserved (never upgraded).
        claims.put(AuthenticationAssurance.CLAIM_AUTH_TIME, r.authTime().getEpochSecond());
        claims.put(AuthenticationAssurance.CLAIM_ACR, r.acr());
        return claims;
    }
}
