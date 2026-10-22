package com.openwolf.iam.authority.approval;

import com.fasterxml.jackson.databind.JsonNode;
import com.openwolf.iam.auth.AuthenticationAssurance;
import com.openwolf.iam.auth.BusinessScopeRegistry;
import com.openwolf.iam.entity.AgentExchangeRoute;
import com.openwolf.iam.entity.AgentWorkloadIdentity;
import com.openwolf.iam.entity.TenantApplicationClient;
import com.openwolf.iam.exception.EntityNotFoundException;
import com.openwolf.iam.exception.ResourceConflictException;
import com.openwolf.iam.repository.AgentExchangeRouteRepository;
import com.openwolf.iam.repository.AgentWorkloadIdentityRepository;
import com.openwolf.iam.repository.PrincipalRepository;
import com.openwolf.iam.service.ApplicationAccessService;
import com.openwolf.iam.service.AuditService;
import com.openwolf.iam.service.TenantApplicationService;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.TreeSet;
import java.util.UUID;

/**
 * Phase 3.7–3.9 and 3.13. A human initiator asks for one exact, structured operation to be executed by one Agent
 * workload at one receiver; an independent approver (not the initiator, holding {@code action_approver}, with fresh
 * authentication) approves exactly that digest; the initiator then confirms it with fresh authentication meeting the
 * approval's assurance requirement (step-up); the Agent redeems it once for a short-lived token bound to the digest.
 * Free-text intent never grants anything: the action type, digest, receiver and scopes do.
 */
@Service
public class ActionApprovalService {
    public static final String PROFILE = "approved_action";
    public static final String APPROVER_ROLE = "action_approver";
    private static final OAuth2Error INVALID_GRANT = new OAuth2Error(OAuth2ErrorCodes.INVALID_GRANT);
    private static final OAuth2Error INVALID_SCOPE = new OAuth2Error(OAuth2ErrorCodes.INVALID_SCOPE);
    private static final OAuth2Error UNAUTHORIZED_CLIENT = new OAuth2Error(OAuth2ErrorCodes.UNAUTHORIZED_CLIENT);

    public record ApprovalView(UUID id, String initiator, UUID agentWorkloadId, String receiverAudience,
                               List<String> scopes, String actionType, String canonicalAction, String actionDigest,
                               List<String> requiredAcr, int maxAuthAgeSeconds, Instant deadline,
                               ActionApproval.Status status, long version, String approver, Instant approvedAt,
                               Instant confirmedAt, Instant consumedAt, Instant endedAt, String endReason) {}

    public record Redemption(UUID approvalId, long version, String tenantId, String initiator, UUID ownerApplicationId,
                             String audience, Set<String> scopes, String actionType, String actionDigest,
                             Instant deadline, Instant authTime, String acr, String workloadId, String workloadRef,
                             String actorClientId) {}

    private final ActionApprovalRepository approvals;
    private final AgentWorkloadIdentityRepository workloads;
    private final AgentExchangeRouteRepository routes;
    private final TenantApplicationService applications;
    private final ApplicationAccessService applicationAccess;
    private final BusinessScopeRegistry businessScopes;
    private final PrincipalRepository principals;
    private final JdbcTemplate jdbc;
    private final AuditService audit;
    private final Clock clock = Clock.systemUTC();
    private final Duration maxDeadline;
    private final Duration maxAuthAgeCeiling;

    public ActionApprovalService(ActionApprovalRepository approvals, AgentWorkloadIdentityRepository workloads,
                                 AgentExchangeRouteRepository routes, TenantApplicationService applications,
                                 ApplicationAccessService applicationAccess, BusinessScopeRegistry businessScopes,
                                 PrincipalRepository principals, JdbcTemplate jdbc, AuditService audit,
                                 @Value("${iam.action-approval.max-deadline:PT1H}") Duration maxDeadline,
                                 @Value("${iam.action-approval.max-auth-age-ceiling:PT15M}") Duration maxAuthAgeCeiling) {
        if (maxDeadline.isNegative() || maxDeadline.isZero() || maxDeadline.compareTo(Duration.ofDays(1)) > 0
                || maxAuthAgeCeiling.isNegative() || maxAuthAgeCeiling.isZero()) {
            throw new IllegalArgumentException("action-approval limits are invalid");
        }
        this.approvals = approvals; this.workloads = workloads; this.routes = routes; this.applications = applications;
        this.applicationAccess = applicationAccess; this.businessScopes = businessScopes; this.principals = principals;
        this.jdbc = jdbc; this.audit = audit; this.maxDeadline = maxDeadline; this.maxAuthAgeCeiling = maxAuthAgeCeiling;
    }

    // =================================================================================================================
    // Request, approve, reject, confirm, revoke
    // =================================================================================================================

    @Transactional
    public ApprovalView request(Jwt initiator, UUID workloadId, String receiverAudience, Collection<String> requestedScopes,
                                String actionType, JsonNode action, long deadlineSeconds, Collection<String> requiredAcr,
                                int maxAuthAgeSeconds) {
        Instant now = clock.instant();
        String tenantId = human(initiator);
        String who = initiator.getSubject();
        requireActive(tenantId, who);
        if (actionType == null || !actionType.matches("[a-z][a-z0-9._-]{1,63}")) {
            throw new IllegalArgumentException("action type is malformed");
        }
        Duration window = Duration.ofSeconds(deadlineSeconds);
        if (window.isNegative() || window.isZero() || window.compareTo(maxDeadline) > 0) {
            throw new IllegalArgumentException("approval deadline exceeds its maximum");
        }
        if (maxAuthAgeSeconds < 1 || Duration.ofSeconds(maxAuthAgeSeconds).compareTo(maxAuthAgeCeiling) > 0) {
            throw new IllegalArgumentException("authentication age requirement is outside the permitted range");
        }
        List<String> acr = requiredAcr == null || requiredAcr.isEmpty() ? List.of(AuthenticationAssurance.PASSWORD)
                : List.copyOf(new TreeSet<>(requiredAcr));
        AgentWorkloadIdentity workload = workloads.findByTenantIdAndId(tenantId, workloadId)
                .filter(this::usable)
                .orElseThrow(() -> new EntityNotFoundException("active agent workload identity not found"));
        TenantApplicationService.ClientAuthority client = agentClient(workload)
                .orElseThrow(() -> new IllegalArgumentException("agent workload client is not active"));
        TreeSet<String> scopes = new TreeSet<>();
        for (String s : requestedScopes) scopes.add(s.trim());
        if (scopes.isEmpty() || scopes.stream().anyMatch(s -> s.isBlank() || !businessScopes.isApproved(tenantId, s))
                || !client.scopes().containsAll(scopes)) {
            throw new IllegalArgumentException("approval scopes must be approved scopes of the agent client");
        }
        String audience = receiverAudience.trim();
        AgentExchangeRoute route = resourceRoute(tenantId, workload.getId(), audience, scopes, now)
                .orElseThrow(() -> new IllegalArgumentException(
                        "the agent has no single active resource route to this receiver covering these scopes"));
        if (!initiatorEntitled(tenantId, client.applicationId(), who, scopes)) {
            throw new AccessDeniedException("initiator does not hold these permissions");
        }
        ActionCanonicalizer.Canonical canonical = ActionCanonicalizer.canonicalize(actionType, audience, action);
        Instant deadline = now.plus(window);
        if (deadline.isAfter(route.getExpiresAt())) deadline = route.getExpiresAt();
        ActionApproval approval = approvals.save(new ActionApproval(tenantId, who, workload.getId(),
                client.applicationId(), route.getId(), audience, List.copyOf(scopes), actionType, canonical, acr,
                maxAuthAgeSeconds, deadline, now));
        audit.logRequired(tenantId, who, "ACTION_APPROVAL_REQUESTED", "action_approval", approval.getId().toString(),
                null, snapshot(approval), approval.getId().toString());
        return view(approval);
    }

    @Transactional
    public ApprovalView approve(Jwt approver, UUID id, String presentedDigest) {
        Instant now = clock.instant();
        String tenantId = human(approver);
        ActionApproval approval = approvals.lock(id, tenantId).orElseThrow(() -> new EntityNotFoundException("approval not found"));
        String who = approver.getSubject();
        if (who.equals(approval.getInitiator())) throw new AccessDeniedException("the initiator cannot approve");
        requireActive(tenantId, who);
        if (!holdsApproverRole(tenantId, who)) throw new AccessDeniedException("approver role required");
        requireAssurance(approver, approval, now);
        requireOpen(approval, now);
        if (!approval.getActionDigest().equals(presentedDigest)) {
            throw new ResourceConflictException("approval is for a different action");
        }
        approval.approve(who, AuthenticationAssurance.authTime(approver).orElseThrow(), now);
        audit.logRequired(tenantId, who, "ACTION_APPROVAL_APPROVED", "action_approval", id.toString(), null,
                Map.of("action_digest", approval.getActionDigest(), "version", approval.getVersion(),
                        "approver_auth_time", AuthenticationAssurance.authTime(approver).orElseThrow().toString()),
                id.toString());
        return view(approval);
    }

    @Transactional
    public ApprovalView reject(Jwt approver, UUID id, String reason) {
        String tenantId = human(approver);
        ActionApproval approval = approvals.lock(id, tenantId).orElseThrow(() -> new EntityNotFoundException("approval not found"));
        String who = approver.getSubject();
        if (who.equals(approval.getInitiator()) || !holdsApproverRole(tenantId, who)) {
            throw new AccessDeniedException("approver role required");
        }
        if (approval.end(ActionApproval.Status.REJECTED, label(reason, "rejected"), clock.instant())) {
            audit.logRequired(tenantId, who, "ACTION_APPROVAL_REJECTED", "action_approval", id.toString(), null,
                    Map.of("reason", label(reason, "rejected")), id.toString());
        }
        return view(approval);
    }

    /** Step-up: the initiator re-confirms the exact action with authentication that meets the approval's requirement. */
    @Transactional
    public ApprovalView confirm(Jwt initiator, UUID id, String presentedDigest) {
        Instant now = clock.instant();
        String tenantId = human(initiator);
        ActionApproval approval = approvals.lock(id, tenantId)
                .filter(a -> a.getInitiator().equals(initiator.getSubject()))
                .orElseThrow(() -> new EntityNotFoundException("approval not found"));
        requireActive(tenantId, initiator.getSubject());
        requireAssurance(initiator, approval, now);
        requireOpen(approval, now);
        if (!approval.getActionDigest().equals(presentedDigest)) {
            throw new ResourceConflictException("approval is for a different action");
        }
        approval.confirm(AuthenticationAssurance.authTime(initiator).orElseThrow(),
                initiator.getClaimAsString(AuthenticationAssurance.CLAIM_ACR), now);
        audit.logRequired(tenantId, initiator.getSubject(), "ACTION_APPROVAL_CONFIRMED", "action_approval",
                id.toString(), null, Map.of("version", approval.getVersion(),
                        "auth_time", approval.getConfirmationAuthTime().toString(),
                        "acr", approval.getConfirmationAcr()), id.toString());
        return view(approval);
    }

    /** The initiator (or an administrator) can withdraw an approval at any time; a consumed approval's token stops. */
    @Transactional
    public ApprovalView revoke(String tenantId, UUID id, String actor, boolean administrator, String reason) {
        ActionApproval approval = approvals.lock(id, tenantId)
                .filter(a -> administrator || a.getInitiator().equals(actor))
                .orElseThrow(() -> new EntityNotFoundException("approval not found"));
        if (approval.end(ActionApproval.Status.REVOKED, label(reason, "revoked"), clock.instant())) {
            audit.logRequired(tenantId, actor, "ACTION_APPROVAL_REVOKED", "action_approval", id.toString(), null,
                    Map.of("reason", label(reason, "revoked"), "version", approval.getVersion()), id.toString());
        }
        return view(approval);
    }

    @Transactional(readOnly = true)
    public ApprovalView get(String tenantId, UUID id, String viewer, boolean administrator) {
        ActionApproval approval = approvals.findByTenantIdAndId(tenantId, id)
                .orElseThrow(() -> new EntityNotFoundException("approval not found"));
        if (!administrator && !viewer.equals(approval.getInitiator()) && !holdsApproverRole(tenantId, viewer)) {
            throw new EntityNotFoundException("approval not found");
        }
        return view(approval);
    }

    // =================================================================================================================
    // Redemption (token endpoint, inside the caller's transaction) and use-time validation
    // =================================================================================================================

    @Transactional(propagation = Propagation.MANDATORY)
    public Redemption redeem(String clientId, UUID id, String presentedDigest, Set<String> requestedScopes) {
        Instant now = clock.instant();
        ActionApproval approval = approvals.findById(id).orElseThrow(() -> new OAuth2AuthenticationException(INVALID_GRANT));
        AgentWorkloadIdentity workload = workloads.findByTenantIdAndId(approval.getTenantId(), approval.getAgentWorkloadId())
                .orElseThrow(() -> new OAuth2AuthenticationException(INVALID_GRANT));
        if (!workload.getOauthClientId().equals(clientId)) throw new OAuth2AuthenticationException(UNAUTHORIZED_CLIENT);
        if (requestedScopes.isEmpty() || !Set.copyOf(approval.getScopes()).containsAll(requestedScopes)) {
            throw new OAuth2AuthenticationException(INVALID_SCOPE);
        }
        requireLive(approval, workload, now);
        if (approvals.consume(id, approval.getTenantId(), presentedDigest, clientId, now) != 1) {
            throw new OAuth2AuthenticationException(INVALID_GRANT);
        }
        return new Redemption(approval.getId(), approval.getVersion() + 1, approval.getTenantId(), approval.getInitiator(),
                approval.getOwnerApplicationId(), approval.getReceiverAudience(), Set.copyOf(requestedScopes),
                approval.getActionType(), approval.getActionDigest(), approval.getDeadline(),
                approval.getConfirmationAuthTime(), approval.getConfirmationAcr(), workload.getId().toString(),
                workload.getWorkloadRef(), clientId);
    }

    /** Introspection-time validation of an approved-action token against the approval's current state. */
    @Transactional(readOnly = true)
    public void requireCurrent(Jwt token) {
        UUID id = uuid(token.getClaimAsString("approval_id"));
        ActionApproval approval = approvals.findById(id).orElseThrow(() -> new OAuth2AuthenticationException(INVALID_GRANT));
        Object version = token.getClaims().get("ap_ver");
        if (approval.getStatus() != ActionApproval.Status.CONSUMED
                || !(version instanceof Number v) || v.longValue() != approval.getVersion()
                || !approval.getTenantId().equals(token.getClaimAsString("tenant_id"))
                || !approval.getInitiator().equals(token.getSubject())
                || !approval.getActionDigest().equals(token.getClaimAsString("action_digest"))
                || !approval.getId().toString().equals(token.getClaimAsString("authority_id"))
                || token.getAudience() == null || token.getAudience().size() != 1
                || !approval.getReceiverAudience().equals(token.getAudience().getFirst())
                || !Objects.equals(approval.getConsumedByClient(), token.getClaimAsString("client_id"))) {
            throw new OAuth2AuthenticationException(INVALID_GRANT);
        }
        // Everything that authorized the redemption must still hold now: workload, its client, the route and the
        // initiator's permission (Phase 3.8 repair: use-time validation, not just the approval row).
        AgentWorkloadIdentity workload = workloads.findByTenantIdAndId(approval.getTenantId(), approval.getAgentWorkloadId())
                .orElseThrow(() -> new OAuth2AuthenticationException(INVALID_GRANT));
        requireLiveAuthority(approval, workload, clock.instant());
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

    private void requireLive(ActionApproval approval, AgentWorkloadIdentity workload, Instant now) {
        if (approval.getStatus() != ActionApproval.Status.CONFIRMED || !now.isBefore(approval.getDeadline())) {
            throw new OAuth2AuthenticationException(INVALID_GRANT);
        }
        requireLiveAuthority(approval, workload, now);
    }

    /** Current authority behind an approval, shared by redemption and every later use (introspection). */
    private void requireLiveAuthority(ActionApproval approval, AgentWorkloadIdentity workload, Instant now) {
        if (!usable(workload)) throw new OAuth2AuthenticationException(INVALID_GRANT);
        TenantApplicationService.ClientAuthority client = agentClient(workload)
                .filter(c -> c.applicationId().equals(approval.getOwnerApplicationId()))
                .orElseThrow(() -> new OAuth2AuthenticationException(INVALID_GRANT));
        Set<String> scopes = Set.copyOf(approval.getScopes());
        boolean routeLive = routes.findByTenantIdAndId(approval.getTenantId(), approval.getRouteId())
                .filter(r -> r.usableAt(now) && r.getDestinationType() == AgentExchangeRoute.DestinationType.RESOURCE)
                .filter(r -> r.getAudience().equals(approval.getReceiverAudience()))
                .filter(r -> r.getAllowedScopes().containsAll(scopes)).isPresent();
        if (!routeLive || !client.scopes().containsAll(scopes)
                || !principalActive(approval.getTenantId(), approval.getInitiator())
                || !initiatorEntitled(approval.getTenantId(), approval.getOwnerApplicationId(), approval.getInitiator(), scopes)) {
            throw new OAuth2AuthenticationException(INVALID_GRANT);
        }
    }

    // =================================================================================================================
    // Helpers
    // =================================================================================================================

    private void requireAssurance(Jwt token, ActionApproval approval, Instant now) {
        if (!AuthenticationAssurance.satisfies(token, approval.getRequiredAcr(),
                Duration.ofSeconds(approval.getMaxAuthAgeSeconds()), now)) {
            throw new AccessDeniedException("fresh authentication meeting the approval's assurance is required");
        }
    }

    private static void requireOpen(ActionApproval approval, Instant now) {
        if (!now.isBefore(approval.getDeadline())) throw new ResourceConflictException("approval deadline passed");
    }

    /** Only a person's own interactive Axiom token, never a delegated, workload or recovery token. */
    private static String human(Jwt token) {
        if (token.getClaims().containsKey("act") || token.getClaims().containsKey("token_use")
                || Boolean.TRUE.equals(token.getClaims().get("impersonation"))
                || Boolean.TRUE.equals(token.getClaims().get("recovery"))) {
            throw new AccessDeniedException("a person's own token is required");
        }
        String tenant = token.getClaimAsString("tenant_id");
        if (tenant == null || tenant.isBlank()) throw new AccessDeniedException("token has no tenant");
        return tenant;
    }

    /** Initiators need the permission itself; co-signed permissions are exactly what an approval unlocks. */
    private boolean initiatorEntitled(String tenantId, UUID applicationId, String who, Set<String> scopes) {
        return applicationAccess.decisionAuthority(tenantId, applicationId, who)
                .map(a -> scopes.stream().allMatch(s -> Set.of("allow", "cosign").contains(a.permissionEffects().get(s))))
                .orElse(false);
    }

    private boolean holdsApproverRole(String tenantId, String who) {
        Integer held = jdbc.queryForObject("SELECT count(*) FROM principal_roles pr JOIN roles r ON r.id = pr.role_id "
                + "WHERE pr.principal_id = ? AND pr.tenant_id = ? AND r.tenant_id = ? AND r.name = ?", Integer.class,
                who, tenantId, tenantId, APPROVER_ROLE);
        return held != null && held > 0;
    }

    private void requireActive(String tenantId, String who) {
        if (!principalActive(tenantId, who)) throw new AccessDeniedException("principal is not active");
    }

    private boolean principalActive(String tenantId, String who) {
        return principals.findById(who).filter(p -> p.isActive() && tenantId.equals(p.getTenantId())).isPresent();
    }

    private java.util.Optional<TenantApplicationService.ClientAuthority> agentClient(AgentWorkloadIdentity workload) {
        return applications.activeAuthority(workload.getOauthClientId())
                .filter(c -> c.tenantId().equals(workload.getTenantId()))
                .filter(c -> c.clientType() == TenantApplicationClient.Type.CONFIDENTIAL_SERVICE);
    }

    private java.util.Optional<AgentExchangeRoute> resourceRoute(String tenantId, UUID workloadId, String audience,
                                                                 Set<String> scopes, Instant now) {
        List<AgentExchangeRoute> matches = routes.findByTenantIdAndSourceWorkloadIdAndAudienceAndStatus(tenantId,
                        workloadId, audience, AgentExchangeRoute.Status.ACTIVE).stream()
                .filter(r -> r.usableAt(now) && r.getDestinationType() == AgentExchangeRoute.DestinationType.RESOURCE)
                .filter(r -> r.getAllowedScopes().containsAll(scopes)).toList();
        return matches.size() == 1 && applications.isActiveAudience(tenantId, audience)
                ? java.util.Optional.of(matches.getFirst()) : java.util.Optional.empty();
    }

    static ApprovalView view(ActionApproval a) {
        return new ApprovalView(a.getId(), a.getInitiator(), a.getAgentWorkloadId(), a.getReceiverAudience(),
                a.getScopes(), a.getActionType(), a.getCanonicalAction(), a.getActionDigest(), a.getRequiredAcr(),
                a.getMaxAuthAgeSeconds(), a.getDeadline(), a.getStatus(), a.getVersion(), a.getApprover(),
                a.getApprovedAt(), a.getConfirmedAt(), a.getConsumedAt(), a.getEndedAt(), a.getEndReason());
    }

    private static Map<String, Object> snapshot(ActionApproval a) {
        Map<String, Object> s = new LinkedHashMap<>();
        s.put("approval_id", a.getId().toString());
        s.put("initiator", a.getInitiator());
        s.put("agent_workload_id", a.getAgentWorkloadId().toString());
        s.put("receiver_audience", a.getReceiverAudience());
        s.put("scopes", a.getScopes());
        s.put("action_type", a.getActionType());
        s.put("action_digest", a.getActionDigest());
        s.put("canonical_version", ActionCanonicalizer.VERSION);
        s.put("required_acr", a.getRequiredAcr());
        s.put("max_auth_age_seconds", a.getMaxAuthAgeSeconds());
        s.put("deadline", a.getDeadline().toString());
        return s;
    }

    private static String label(String value, String fallback) {
        if (value == null || value.isBlank()) return fallback;
        String v = value.strip();
        return v.length() > 200 ? v.substring(0, 200) : v;
    }

    private static UUID uuid(String value) {
        try {
            return UUID.fromString(Objects.requireNonNull(value));
        } catch (RuntimeException malformed) {
            throw new OAuth2AuthenticationException(INVALID_GRANT);
        }
    }
}
