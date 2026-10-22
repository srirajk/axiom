package com.openwolf.iam.authority.standing;

import com.openwolf.iam.auth.AuthenticationAssurance;
import com.openwolf.iam.auth.BusinessScopeRegistry;
import com.openwolf.iam.entity.AgentExchangeRoute;
import com.openwolf.iam.entity.AgentWorkloadIdentity;
import com.openwolf.iam.entity.TenantApplicationClient;
import com.openwolf.iam.exception.EntityNotFoundException;
import com.openwolf.iam.repository.AgentExchangeRouteRepository;
import com.openwolf.iam.repository.AgentWorkloadIdentityRepository;
import com.openwolf.iam.repository.PrincipalRepository;
import com.openwolf.iam.security.SecretProtector;
import com.openwolf.iam.service.ApplicationAccessService;
import com.openwolf.iam.service.AuditService;
import com.openwolf.iam.service.TenantApplicationService;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.TreeSet;
import java.util.UUID;

/**
 * Phase 3.3 standing offline authority. An owner explicitly approves (with fresh interactive authentication) that one
 * Agent workload may act for them, offline, towards one resource audience it already has a server-owned route to,
 * with a fixed scope set, until a fixed expiry. The workload redeems the grant with its own client authentication
 * plus a single-use, rotating renewal handle; an access token is never renewal material. Every redemption and every
 * use re-reads current state: withdrawal, expiry, owner disable, entitlement loss, route or workload loss each stop it.
 */
@Service
public class StandingGrantService {
    public static final String PROFILE = "standing_grant";
    public static final String CLAIM_GRANT = "standing_grant_id";
    public static final String CLAIM_VERSION = "sg_ver";
    public static final String CLAIM_TASK = "task_id";
    private static final OAuth2Error INVALID_GRANT = new OAuth2Error(OAuth2ErrorCodes.INVALID_GRANT);
    private static final OAuth2Error INVALID_SCOPE = new OAuth2Error(OAuth2ErrorCodes.INVALID_SCOPE);
    private static final OAuth2Error UNAUTHORIZED_CLIENT = new OAuth2Error(OAuth2ErrorCodes.UNAUTHORIZED_CLIENT);

    public record GrantView(UUID id, String ownerPrincipalId, UUID agentWorkloadId, UUID routeId, String audience,
                            List<String> scopes, String purpose, StandingGrant.Status status, long version,
                            Instant approvedAt, Instant expiresAt, Instant claimedAt, Instant lastRenewedAt,
                            long handleGeneration, Instant revokedAt, String revocationReason) {}

    /** Server-resolved result of one redemption; {@code renewalHandle} is shown to the workload exactly once. */
    public record Redemption(UUID grantId, long version, String tenantId, String owner, UUID ownerApplicationId,
                             String audience, Set<String> scopes, Instant expiresAt, String workloadId,
                             String workloadRef, String actorClientId, String renewalHandle, long generation,
                             UUID taskId) {
        @Override
        public String toString() { return "Redemption[grantId=" + grantId + ", generation=" + generation + "]"; }
    }

    /** Thrown after a committed security side effect (reuse revocation): the caller must commit, then deny. */
    public static final class ReuseDetected extends RuntimeException {
        ReuseDetected() { super("renewal handle reuse", null, false, false); }
    }

    private final StandingGrantRepository grants;
    private final AgentWorkloadIdentityRepository workloads;
    private final AgentExchangeRouteRepository routes;
    private final TenantApplicationService applications;
    private final ApplicationAccessService applicationAccess;
    private final BusinessScopeRegistry businessScopes;
    private final PrincipalRepository principals;
    private final SecretProtector secrets;
    private final AuditService audit;
    private final Clock clock;
    private final Duration maxLifetime;
    private final Duration approvalMaxAuthAge;
    private final SecureRandom random = new SecureRandom();

    @org.springframework.beans.factory.annotation.Autowired
    public StandingGrantService(StandingGrantRepository grants, AgentWorkloadIdentityRepository workloads,
                                AgentExchangeRouteRepository routes, TenantApplicationService applications,
                                ApplicationAccessService applicationAccess, BusinessScopeRegistry businessScopes,
                                PrincipalRepository principals, SecretProtector secrets, AuditService audit,
                                @Value("${iam.standing-grant.max-lifetime:P30D}") Duration maxLifetime,
                                @Value("${iam.standing-grant.approval-max-auth-age:PT15M}") Duration approvalMaxAuthAge) {
        this(grants, workloads, routes, applications, applicationAccess, businessScopes, principals, secrets, audit,
                Clock.systemUTC(), maxLifetime, approvalMaxAuthAge);
    }

    StandingGrantService(StandingGrantRepository grants, AgentWorkloadIdentityRepository workloads,
                         AgentExchangeRouteRepository routes, TenantApplicationService applications,
                         ApplicationAccessService applicationAccess, BusinessScopeRegistry businessScopes,
                         PrincipalRepository principals, SecretProtector secrets, AuditService audit, Clock clock,
                         Duration maxLifetime, Duration approvalMaxAuthAge) {
        if (maxLifetime.isNegative() || maxLifetime.isZero() || maxLifetime.compareTo(Duration.ofDays(90)) > 0
                || approvalMaxAuthAge.isNegative() || approvalMaxAuthAge.isZero()) {
            throw new IllegalArgumentException("standing-grant limits are invalid");
        }
        this.grants = grants; this.workloads = workloads; this.routes = routes; this.applications = applications;
        this.applicationAccess = applicationAccess; this.businessScopes = businessScopes; this.principals = principals;
        this.secrets = secrets; this.audit = audit; this.clock = clock; this.maxLifetime = maxLifetime;
        this.approvalMaxAuthAge = approvalMaxAuthAge;
    }

    // =================================================================================================================
    // Owner approval and withdrawal
    // =================================================================================================================

    @Transactional
    public GrantView approve(Jwt owner, UUID workloadId, String audience, Collection<String> requestedScopes,
                             String purpose, Instant expiresAt) {
        Instant now = clock.instant();
        String tenantId = requiredClaim(owner, "tenant_id");
        String ownerId = owner.getSubject();
        // Explicit owner approval: the owner's own interactive authentication, recently, never a delegated token.
        if (owner.getClaims().containsKey("act") || owner.getClaims().containsKey("token_use")
                || !AuthenticationAssurance.satisfies(owner, Set.of(AuthenticationAssurance.PASSWORD), approvalMaxAuthAge, now)) {
            throw new AccessDeniedException("standing-grant approval requires recent interactive authentication");
        }
        requireActiveOwner(tenantId, ownerId);
        AgentWorkloadIdentity workload = workloads.findByTenantIdAndId(tenantId, workloadId)
                .filter(this::usable)
                .orElseThrow(() -> new EntityNotFoundException("active agent workload identity not found"));
        TenantApplicationService.ClientAuthority client = agentClient(workload)
                .orElseThrow(() -> new IllegalArgumentException("agent workload client is not active"));
        TreeSet<String> scopes = new TreeSet<>();
        for (String scope : requestedScopes) scopes.add(scope.trim());
        if (scopes.isEmpty() || scopes.stream().anyMatch(s -> s.isBlank() || !businessScopes.isApproved(tenantId, s))
                || !client.scopes().containsAll(scopes)) {
            throw new IllegalArgumentException("standing scopes must be approved scopes of the agent client");
        }
        AgentExchangeRoute route = resourceRoute(tenantId, workload.getId(), audience.trim(), scopes, now)
                .orElseThrow(() -> new IllegalArgumentException(
                        "the agent has no single active resource route to this audience covering these scopes"));
        if (!ownerEntitled(tenantId, client.applicationId(), ownerId, scopes)) {
            throw new AccessDeniedException("owner does not currently hold these permissions");
        }
        Instant ceiling = earliest(now.plus(maxLifetime), route.getExpiresAt());
        if (expiresAt == null || !expiresAt.isAfter(now) || expiresAt.isAfter(ceiling)) {
            throw new IllegalArgumentException("standing grant expiry exceeds its maximum lifetime or route expiry");
        }
        StandingGrant grant = grants.save(new StandingGrant(tenantId, ownerId, client.applicationId(), workload.getId(),
                route.getId(), route.getAudience(), List.copyOf(scopes), purpose.trim(),
                AuthenticationAssurance.authTime(owner).orElseThrow(), expiresAt, now));
        audit.logRequired(tenantId, ownerId, "STANDING_GRANT_APPROVED", "standing_grant", grant.getId().toString(),
                null, snapshot(grant), grant.getId().toString());
        return view(grant);
    }

    @Transactional(readOnly = true)
    public List<GrantView> listForOwner(Jwt owner) {
        return grants.findByTenantIdAndOwnerPrincipalIdOrderByCreatedAtDesc(requiredClaim(owner, "tenant_id"),
                owner.getSubject()).stream().map(StandingGrantService::view).toList();
    }

    @Transactional(readOnly = true)
    public List<GrantView> list(String tenantId) {
        return grants.findByTenantIdOrderByCreatedAtDesc(tenantId).stream().map(StandingGrantService::view).toList();
    }

    /** Owner withdrawal. */
    @Transactional
    public GrantView revokeByOwner(Jwt owner, UUID grantId, String reason) {
        String tenantId = requiredClaim(owner, "tenant_id");
        StandingGrant grant = grants.lock(grantId).filter(g -> g.getTenantId().equals(tenantId))
                .filter(g -> g.getOwnerPrincipalId().equals(owner.getSubject()))
                .orElseThrow(() -> new EntityNotFoundException("standing grant not found"));
        return revoke(grant, reason, owner.getSubject());
    }

    /** Administrative withdrawal (an administrator can withdraw, never approve, a standing grant). */
    @Transactional
    public GrantView revokeByAdministrator(String tenantId, UUID grantId, String reason, String actor) {
        StandingGrant grant = grants.lock(grantId).filter(g -> g.getTenantId().equals(tenantId))
                .orElseThrow(() -> new EntityNotFoundException("standing grant not found"));
        return revoke(grant, reason, actor);
    }

    private GrantView revoke(StandingGrant grant, String reason, String actor) {
        String why = reason == null || reason.isBlank() ? "withdrawn" : truncate(reason.strip());
        if (grant.revoke(why, clock.instant())) {
            audit.logRequired(grant.getTenantId(), actor, "STANDING_GRANT_REVOKED", "standing_grant",
                    grant.getId().toString(), null, Map.of("reason", why, "version", grant.getVersion()),
                    grant.getId().toString());
        }
        return view(grant);
    }

    // =================================================================================================================
    // Redemption (token endpoint) — runs inside the caller's PostgreSQL transaction, which commits only after the
    // token is signed and its Redis record written (ordering, not cross-store atomicity; see the provider).
    // =================================================================================================================

    /** Reuse revocation must commit even though the redemption is refused, hence {@code noRollbackFor}. */
    @Transactional(propagation = Propagation.MANDATORY, noRollbackFor = ReuseDetected.class)
    public Redemption redeem(String clientId, UUID grantId, String presentedHandle, Set<String> requestedScopes,
                             UUID taskId, TaskBinding tasks) {
        Instant now = clock.instant();
        StandingGrant grant = grants.lock(grantId).orElseThrow(() -> new OAuth2AuthenticationException(INVALID_GRANT));
        AgentWorkloadIdentity workload = workloads.findByTenantIdAndId(grant.getTenantId(), grant.getAgentWorkloadId())
                .orElseThrow(() -> new OAuth2AuthenticationException(INVALID_GRANT));
        if (!workload.getOauthClientId().equals(clientId)) throw new OAuth2AuthenticationException(UNAUTHORIZED_CLIENT);
        if (grant.getStatus() == StandingGrant.Status.REVOKED) throw new OAuth2AuthenticationException(INVALID_GRANT);
        if (grant.getStatus() == StandingGrant.Status.APPROVED) {
            if (presentedHandle != null) throw new OAuth2AuthenticationException(INVALID_GRANT);
        } else {
            String digest = presentedHandle == null ? null : secrets.keyedDigest("standing-grant-handle", presentedHandle);
            if (digest == null) throw new OAuth2AuthenticationException(INVALID_GRANT);
            if (!digest.equals(grant.getHandleDigest())) {
                if (digest.equals(grant.getPreviousHandleDigest())) {
                    // A superseded handle came back: it was copied. Withdraw the grant (committed by the caller).
                    revoke(grant, "renewal handle reuse detected", "system");
                    throw new ReuseDetected();
                }
                throw new OAuth2AuthenticationException(INVALID_GRANT);
            }
        }
        requireCurrent(grant, workload, now);
        if (requestedScopes.isEmpty() || !Set.copyOf(grant.getScopes()).containsAll(requestedScopes)) {
            throw new OAuth2AuthenticationException(INVALID_SCOPE);
        }
        if (taskId != null && (tasks == null || !tasks.boundToStandingGrant(grant.getTenantId(), taskId,
                grant.getId(), grant.getVersion(), workload.getId()))) {
            throw new OAuth2AuthenticationException(INVALID_GRANT);
        }
        String handle = newHandle();
        grant.rotate(secrets.keyedDigest("standing-grant-handle", handle), now);
        return new Redemption(grant.getId(), grant.getVersion(), grant.getTenantId(), grant.getOwnerPrincipalId(),
                grant.getOwnerApplicationId(), grant.getAudience(), Set.copyOf(requestedScopes), grant.getExpiresAt(),
                workload.getId().toString(), workload.getWorkloadRef(), clientId, handle, grant.getHandleGeneration(),
                taskId);
    }

    /** Durable-task coupling, implemented by the task service. */
    public interface TaskBinding {
        boolean boundToStandingGrant(String tenantId, UUID taskId, UUID grantId, long grantVersion, UUID workloadId);
    }

    // =================================================================================================================
    // Use-time validation (introspection, task resume)
    // =================================================================================================================

    /** Validates a standing-grant token against current state; any mismatch fails closed. */
    @Transactional(readOnly = true)
    public void requireCurrent(Jwt token, TaskBinding tasks) {
        Instant now = clock.instant();
        UUID grantId = uuid(token.getClaimAsString(CLAIM_GRANT));
        Object version = token.getClaims().get(CLAIM_VERSION);
        StandingGrant grant = grants.findById(grantId).orElseThrow(() -> new OAuth2AuthenticationException(INVALID_GRANT));
        if (!(version instanceof Number v) || v.longValue() != grant.getVersion()
                || grant.getStatus() != StandingGrant.Status.ACTIVE
                || !grant.getTenantId().equals(token.getClaimAsString("tenant_id"))
                || !grant.getOwnerPrincipalId().equals(token.getSubject())
                || token.getAudience() == null || token.getAudience().size() != 1
                || !grant.getAudience().equals(token.getAudience().getFirst())
                || !grant.getId().toString().equals(token.getClaimAsString("authority_id"))
                || !Set.copyOf(grant.getScopes()).containsAll(scopes(token))) {
            throw new OAuth2AuthenticationException(INVALID_GRANT);
        }
        AgentWorkloadIdentity workload = workloads.findByTenantIdAndId(grant.getTenantId(), grant.getAgentWorkloadId())
                .orElseThrow(() -> new OAuth2AuthenticationException(INVALID_GRANT));
        Object act = token.getClaims().get("act");
        if (!(act instanceof Map<?, ?> actor) || !workload.getId().toString().equals(String.valueOf(actor.get("workload_id")))
                || !workload.getOauthClientId().equals(String.valueOf(actor.get("client_id")))
                || !workload.getOauthClientId().equals(token.getClaimAsString("client_id"))) {
            throw new OAuth2AuthenticationException(INVALID_GRANT);
        }
        requireCurrent(grant, workload, now);
        String task = token.getClaimAsString(CLAIM_TASK);
        if (task != null && (tasks == null || !tasks.boundToStandingGrant(grant.getTenantId(), uuid(task), grant.getId(),
                grant.getVersion(), workload.getId()))) {
            throw new OAuth2AuthenticationException(INVALID_GRANT);
        }
    }

    /** Current usability of a grant for a task resume; returns its version. */
    @Transactional(readOnly = true)
    public long currentVersion(String tenantId, UUID grantId, UUID workloadId) {
        StandingGrant grant = grants.findByTenantIdAndId(tenantId, grantId)
                .filter(g -> g.getAgentWorkloadId().equals(workloadId))
                .filter(g -> g.getStatus() != StandingGrant.Status.REVOKED)
                .orElseThrow(() -> new AccessDeniedException("standing grant is not current"));
        AgentWorkloadIdentity workload = workloads.findByTenantIdAndId(tenantId, workloadId)
                .orElseThrow(() -> new AccessDeniedException("standing grant is not current"));
        try {
            requireCurrent(grant, workload, clock.instant());
        } catch (OAuth2AuthenticationException denied) {
            throw new AccessDeniedException("standing grant is not current");
        }
        return grant.getVersion();
    }

    @Transactional(readOnly = true)
    public String ownerOf(String tenantId, UUID grantId) {
        return grants.findByTenantIdAndId(tenantId, grantId).map(StandingGrant::getOwnerPrincipalId)
                .orElseThrow(() -> new AccessDeniedException("standing grant is not current"));
    }


    private com.openwolf.iam.authority.lifecycle.WorkloadLifecycleService lifecycle;

    @org.springframework.beans.factory.annotation.Autowired(required = false)
    void setLifecycle(@org.springframework.context.annotation.Lazy com.openwolf.iam.authority.lifecycle.WorkloadLifecycleService lifecycle) {
        this.lifecycle = lifecycle;
    }

    /** ACTIVE and, once ownership is assigned, still validly owned (Phase 3.10/3.15). */
    private boolean usable(com.openwolf.iam.entity.AgentWorkloadIdentity workload) {
        return lifecycle == null ? workload.getStatus() == com.openwolf.iam.entity.AgentWorkloadIdentity.Status.ACTIVE
                : lifecycle.usable(workload);
    }

    private void requireCurrent(StandingGrant grant, AgentWorkloadIdentity workload, Instant now) {
        if (!now.isBefore(grant.getExpiresAt()) || !usable(workload)) {
            throw new OAuth2AuthenticationException(INVALID_GRANT);
        }
        TenantApplicationService.ClientAuthority client = agentClient(workload)
                .filter(value -> value.applicationId().equals(grant.getOwnerApplicationId()))
                .orElseThrow(() -> new OAuth2AuthenticationException(INVALID_GRANT));
        Set<String> scopes = Set.copyOf(grant.getScopes());
        if (!client.scopes().containsAll(scopes)) throw new OAuth2AuthenticationException(INVALID_GRANT);
        AgentExchangeRoute route = routes.findByTenantIdAndId(grant.getTenantId(), grant.getRouteId())
                .filter(r -> r.usableAt(now))
                .filter(r -> r.getDestinationType() == AgentExchangeRoute.DestinationType.RESOURCE)
                .filter(r -> r.getSourceWorkloadId().equals(workload.getId()))
                .filter(r -> r.getAudience().equals(grant.getAudience()))
                .filter(r -> r.getAllowedScopes().containsAll(scopes))
                .orElseThrow(() -> new OAuth2AuthenticationException(INVALID_GRANT));
        if (!applications.isActiveAudience(grant.getTenantId(), route.getAudience())
                || !principalActive(grant.getTenantId(), grant.getOwnerPrincipalId())
                || !ownerEntitled(grant.getTenantId(), grant.getOwnerApplicationId(), grant.getOwnerPrincipalId(), scopes)) {
            throw new OAuth2AuthenticationException(INVALID_GRANT);
        }
    }

    // =================================================================================================================
    // Helpers
    // =================================================================================================================

    /**
     * Standing authority never exceeds what the owner holds now, and only unconditional ({@code allow}) permissions
     * can be exercised offline: read-only, scoped or co-signed permissions need the owner present.
     */
    private boolean ownerEntitled(String tenantId, UUID applicationId, String owner, Set<String> scopes) {
        return applicationAccess.decisionAuthority(tenantId, applicationId, owner)
                .map(authority -> scopes.stream().allMatch(s -> "allow".equals(authority.permissionEffects().get(s))))
                .orElse(false);
    }

    private void requireActiveOwner(String tenantId, String owner) {
        if (!principalActive(tenantId, owner)) throw new AccessDeniedException("owner is not an active principal");
    }

    private boolean principalActive(String tenantId, String owner) {
        return principals.findById(owner).filter(p -> p.isActive() && tenantId.equals(p.getTenantId())).isPresent();
    }

    private java.util.Optional<TenantApplicationService.ClientAuthority> agentClient(AgentWorkloadIdentity workload) {
        return applications.activeAuthority(workload.getOauthClientId())
                .filter(value -> value.tenantId().equals(workload.getTenantId()))
                .filter(value -> value.clientType() == TenantApplicationClient.Type.CONFIDENTIAL_SERVICE);
    }

    private java.util.Optional<AgentExchangeRoute> resourceRoute(String tenantId, UUID workloadId, String audience,
                                                                 Set<String> scopes, Instant now) {
        List<AgentExchangeRoute> matches = routes.findByTenantIdAndSourceWorkloadIdAndAudienceAndStatus(tenantId,
                        workloadId, audience, AgentExchangeRoute.Status.ACTIVE).stream()
                .filter(r -> r.usableAt(now))
                .filter(r -> r.getDestinationType() == AgentExchangeRoute.DestinationType.RESOURCE)
                .filter(r -> r.getAllowedScopes().containsAll(scopes)).toList();
        return matches.size() == 1 && applications.isActiveAudience(tenantId, audience)
                ? java.util.Optional.of(matches.getFirst()) : java.util.Optional.empty();
    }

    private String newHandle() {
        byte[] bytes = new byte[32];
        random.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    static GrantView view(StandingGrant g) {
        return new GrantView(g.getId(), g.getOwnerPrincipalId(), g.getAgentWorkloadId(), g.getRouteId(), g.getAudience(),
                g.getScopes(), g.getPurpose(), g.getStatus(), g.getVersion(), g.getApprovedAt(), g.getExpiresAt(),
                g.getClaimedAt(), g.getLastRenewedAt(), g.getHandleGeneration(), g.getRevokedAt(),
                g.getRevocationReason());
    }

    private static Map<String, Object> snapshot(StandingGrant g) {
        Map<String, Object> s = new LinkedHashMap<>();
        s.put("grant_id", g.getId().toString());
        s.put("owner", g.getOwnerPrincipalId());
        s.put("agent_workload_id", g.getAgentWorkloadId().toString());
        s.put("route_id", g.getRouteId().toString());
        s.put("audience", g.getAudience());
        s.put("scopes", g.getScopes());
        s.put("version", g.getVersion());
        s.put("expires_at", g.getExpiresAt().toString());
        s.put("approved_auth_time", g.getApprovedAuthTime().toString());
        return s;
    }

    static Set<String> scopes(Jwt jwt) {
        Object raw = jwt.getClaims().get("scope");
        Set<String> result = new LinkedHashSet<>();
        if (raw instanceof String value) {
            for (String s : value.trim().split("\\s+")) if (!s.isBlank()) result.add(s);
        } else if (raw instanceof Collection<?> values) {
            values.forEach(v -> result.add(String.valueOf(v)));
        }
        return result;
    }

    private static String requiredClaim(Jwt jwt, String name) {
        String value = jwt.getClaimAsString(name);
        if (value == null || value.isBlank()) throw new AccessDeniedException("token is missing " + name);
        return value;
    }

    private static UUID uuid(String value) {
        try {
            return UUID.fromString(Objects.requireNonNull(value));
        } catch (RuntimeException malformed) {
            throw new OAuth2AuthenticationException(INVALID_GRANT);
        }
    }

    private static Instant earliest(Instant a, Instant b) { return a.isBefore(b) ? a : b; }

    private static String truncate(String value) { return value.length() > 200 ? value.substring(0, 200) : value; }
}
