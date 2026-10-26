package com.openwolf.iam.service;

import com.openwolf.iam.auth.BusinessScopeRegistry;
import com.openwolf.iam.auth.TokenExchangeConstants;
import com.openwolf.iam.dto.AgentExchangeContracts.AgentExchangeRouteResponse;
import com.openwolf.iam.dto.AgentExchangeContracts.CreateAgentExchangeRouteRequest;
import com.openwolf.iam.dto.AgentExchangeContracts.RegisterTrustedBrokerRequest;
import com.openwolf.iam.dto.AgentExchangeContracts.TrustedBrokerResponse;
import com.openwolf.iam.entity.AgentExchangeRoute;
import com.openwolf.iam.entity.AgentWorkloadIdentity;
import com.openwolf.iam.entity.TenantApplicationClient;
import com.openwolf.iam.entity.TrustedExchangeBroker;
import com.openwolf.iam.entity.TrustedExchangeBrokerTarget;
import com.openwolf.iam.exception.EntityNotFoundException;
import com.openwolf.iam.exception.ResourceConflictException;
import com.openwolf.iam.repository.AgentExchangeRouteRepository;
import com.openwolf.iam.repository.AgentWorkloadIdentityRepository;
import com.openwolf.iam.repository.TrustedExchangeBrokerRepository;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.UUID;

/** Resolves the three explicit, server-owned RFC 8693 authority profiles. */
@Service
@Transactional
public class AgentExchangeAuthorityService {
    private static final Duration MAX_ROUTE_LIFETIME = Duration.ofDays(90);
    private static final OAuth2Error INVALID_GRANT = new OAuth2Error(OAuth2ErrorCodes.INVALID_GRANT);
    private static final OAuth2Error INVALID_SCOPE = new OAuth2Error(OAuth2ErrorCodes.INVALID_SCOPE);
    private static final OAuth2Error INVALID_TARGET = new OAuth2Error("invalid_target");
    private static final OAuth2Error UNAUTHORIZED_CLIENT = new OAuth2Error(OAuth2ErrorCodes.UNAUTHORIZED_CLIENT);

    /**
     * {@code CUSTOMER_SESSION}: a customer's browser-login token (OIDC authorization code through a customer-facing
     * client) redeemed by a workload of the same application; the customer stays the subject and the chain continues
     * along explicit edges exactly like {@code WORKFORCE}. {@code CIAM_CUSTOMER} is the separate, optional consent-grant
     * extension (terminal tokens).
     */
    public enum Profile { CIAM_CUSTOMER, WORKFORCE, WORKLOAD_CONTINUATION, GATEWAY_BACKEND, CUSTOMER_SESSION }
    public enum TokenUse { DELEGATED_ACCESS, EXCHANGE_SUBJECT, GATEWAY_AUTHORIZATION }

    public record ResolvedAuthority(
            Profile profile, TokenUse tokenUse, Jwt subject, String tenantId, String audience,
            Set<String> scopes, String identityKind, String purpose, String authorityId,
            String delegationId, AgentWorkloadIdentity actingWorkload, Instant authorityExpiresAt,
            String routeId, AgentExchangeRoute.DestinationType destinationType) {
        public ResolvedAuthority {
            scopes = Set.copyOf(scopes);
        }
    }

    /** Verified route context for denial audit; a missing/ambiguous route has no selected ID. */
    public static final class RouteDenied extends OAuth2AuthenticationException {
        private final String routeId;
        private final AgentExchangeRoute.DestinationType destinationType;

        RouteDenied(OAuth2Error error, String routeId, AgentExchangeRoute.DestinationType destinationType) {
            super(error);
            this.routeId = routeId;
            this.destinationType = destinationType;
        }

        public String routeId() { return routeId; }
        public AgentExchangeRoute.DestinationType destinationType() { return destinationType; }
    }

    private final TrustedExchangeBrokerRepository brokers;
    private final AgentExchangeRouteRepository routes;
    private final AgentWorkloadIdentityRepository workloads;
    private final TenantApplicationService applications;
    private final ApplicationAccessService applicationAccess;
    private final CiamDelegationAuthorityService customerAuthority;
    private final CiamLifecycleAuditService audit;
    private final BusinessScopeRegistry businessScopes;
    private final Clock clock;
    private TrustedBrokerTargetService brokerTargets;

    @org.springframework.beans.factory.annotation.Autowired
    void setBrokerTargets(TrustedBrokerTargetService brokerTargets) {
        this.brokerTargets = brokerTargets;
    }

    @org.springframework.beans.factory.annotation.Autowired
    public AgentExchangeAuthorityService(
            TrustedExchangeBrokerRepository brokers,
            AgentExchangeRouteRepository routes,
            AgentWorkloadIdentityRepository workloads,
            TenantApplicationService applications,
            ApplicationAccessService applicationAccess,
            CiamDelegationAuthorityService customerAuthority,
            CiamLifecycleAuditService audit,
            BusinessScopeRegistry businessScopes) {
        this(brokers, routes, workloads, applications, applicationAccess, customerAuthority,
                audit, businessScopes, Clock.systemUTC());
    }

    AgentExchangeAuthorityService(
            TrustedExchangeBrokerRepository brokers,
            AgentExchangeRouteRepository routes,
            AgentWorkloadIdentityRepository workloads,
            TenantApplicationService applications,
            ApplicationAccessService applicationAccess,
            CiamDelegationAuthorityService customerAuthority,
            CiamLifecycleAuditService audit,
            BusinessScopeRegistry businessScopes,
            Clock clock) {
        this.brokers = brokers;
        this.routes = routes;
        this.workloads = workloads;
        this.applications = applications;
        this.applicationAccess = applicationAccess;
        this.customerAuthority = customerAuthority;
        this.audit = audit;
        this.businessScopes = businessScopes;
        this.clock = clock;
    }

    public TrustedBrokerResponse registerBroker(String tenantId, RegisterTrustedBrokerRequest request,
                                                 String actorId, String correlationId) {
        String clientId = request.oauthClientId().trim();
        applications.lockClientForIdentityRegistration(clientId);
        if (workloads.findByOauthClientId(clientId).isPresent()) {
            throw new ResourceConflictException("trusted Gateway broker cannot be an Agent workload");
        }
        if (brokers.findByTenantIdAndOauthClientId(tenantId, clientId).isPresent()) {
            throw new ResourceConflictException("trusted Gateway broker client already exists");
        }
        TreeSet<String> scopes = approvedScopes(tenantId, request.scopes());
        var client = confidentialAuthority(clientId, tenantId);
        if (!client.audience().equals(request.gatewayAudience().trim()) || !client.scopes().containsAll(scopes)) {
            throw new IllegalArgumentException("broker audience or scopes exceed its registered client authority");
        }
        TrustedExchangeBroker broker = brokers.save(new TrustedExchangeBroker(tenantId, clientId,
                request.gatewayAudience().trim(), scopes.stream().toList(), clock.instant()));
        audit.record(tenantId, actorId, "TRUSTED_EXCHANGE_BROKER_REGISTERED", "trusted_exchange_broker",
                broker.getId().toString(), Map.of("clientId", clientId,
                        "gatewayAudience", broker.getGatewayAudience(), "scopes", scopes), correlationId);
        return response(broker);
    }

    @Transactional(readOnly = true)
    public List<TrustedBrokerResponse> listBrokers(String tenantId) {
        return brokers.findByTenantIdOrderByCreatedAtAsc(tenantId).stream().map(AgentExchangeAuthorityService::response).toList();
    }

    public TrustedBrokerResponse revokeBroker(String tenantId, UUID brokerId, String actorId, String correlationId) {
        TrustedExchangeBroker broker = brokers.findById(brokerId)
                .filter(value -> value.getTenantId().equals(tenantId))
                .orElseThrow(() -> EntityNotFoundException.forId("Trusted exchange broker", brokerId));
        boolean changed = broker.getStatus() == TrustedExchangeBroker.Status.ACTIVE;
        broker.revoke(clock.instant());
        if (changed) audit.record(tenantId, actorId, "TRUSTED_EXCHANGE_BROKER_REVOKED", "trusted_exchange_broker",
                brokerId.toString(), Map.of("clientId", broker.getOauthClientId()), correlationId);
        return response(broker);
    }

    public AgentExchangeRouteResponse createRoute(String tenantId, CreateAgentExchangeRouteRequest request,
                                                   String actorId, String correlationId) {
        Instant now = clock.instant();
        if (!request.expiresAt().isAfter(now) || request.expiresAt().isAfter(now.plus(MAX_ROUTE_LIFETIME))) {
            throw new IllegalArgumentException("exchange route expiry must be within 90 days");
        }
        AgentWorkloadIdentity source = activeWorkload(tenantId, request.sourceWorkloadId());
        TreeSet<String> scopes = approvedScopes(tenantId, request.scopes());
        var sourceClient = confidentialAuthority(source.getOauthClientId(), tenantId);
        if (!sourceClient.scopes().containsAll(scopes)) {
            throw new IllegalArgumentException("route scopes exceed source workload authority");
        }
        UUID destinationId = request.destinationWorkloadId();
        String audience = request.audience().trim();
        switch (request.destinationType()) {
            case AGENT -> {
                if (destinationId == null || destinationId.equals(source.getId())) {
                    throw new IllegalArgumentException("Agent route requires a different destination workload");
                }
                AgentWorkloadIdentity destination = activeWorkload(tenantId, destinationId);
                var destinationClient = confidentialAuthority(destination.getOauthClientId(), tenantId);
                if (!destinationClient.audience().equals(audience) || !destinationClient.scopes().containsAll(scopes)) {
                    throw new IllegalArgumentException("Agent route exceeds destination workload authority");
                }
            }
            case GATEWAY -> {
                if (destinationId != null) throw new IllegalArgumentException("Gateway route cannot name an Agent workload");
                // Keep the broker active/trusted, but its own OAuth scopes do not define the business scopes
                // a workload may carry through it. The route remains the workload-to-Gateway scope ceiling.
                activeBrokerByAudience(tenantId, audience);
            }
            case RESOURCE -> {
                if (destinationId != null) throw new IllegalArgumentException("Resource route cannot name an Agent workload");
                if (!applications.isActiveAudience(tenantId, audience)) {
                    throw new IllegalArgumentException("Resource route must target an active tenant application audience");
                }
            }
        }
        AgentExchangeRoute route = routes.save(new AgentExchangeRoute(tenantId, source.getId(),
                request.destinationType(), destinationId, audience, scopes.stream().toList(),
                request.purpose().trim(), request.expiresAt(), now));
        audit.record(tenantId, actorId, "AGENT_EXCHANGE_ROUTE_CREATED", "agent_exchange_route",
                route.getId().toString(), routeAuditDetails(route), correlationId);
        return response(route);
    }

    @Transactional(readOnly = true)
    public List<AgentExchangeRouteResponse> listRoutes(String tenantId) {
        return routes.findByTenantIdOrderByCreatedAtAsc(tenantId).stream().map(this::response).toList();
    }

    public AgentExchangeRouteResponse revokeRoute(String tenantId, UUID routeId, String actorId, String correlationId) {
        AgentExchangeRoute route = routes.findByTenantIdAndId(tenantId, routeId)
                .orElseThrow(() -> EntityNotFoundException.forId("Agent exchange route", routeId));
        boolean changed = route.getStatus() == AgentExchangeRoute.Status.ACTIVE;
        route.revoke(clock.instant());
        if (changed) audit.record(tenantId, actorId, "AGENT_EXCHANGE_ROUTE_REVOKED", "agent_exchange_route",
                routeId.toString(), routeAuditDetails(route), correlationId);
        return response(route);
    }

    private static Map<String, Object> routeAuditDetails(AgentExchangeRoute route) {
        Map<String, Object> details = new LinkedHashMap<>();
        details.put("sourceWorkloadId", route.getSourceWorkloadId());
        details.put("destinationType", route.getDestinationType());
        if (route.getDestinationWorkloadId() != null) {
            details.put("destinationWorkloadId", route.getDestinationWorkloadId());
        }
        details.put("audience", route.getAudience());
        details.put("scopes", route.getAllowedScopes());
        details.put("expiresAt", route.getExpiresAt());
        return details;
    }

    @Transactional(readOnly = true)
    public ResolvedAuthority resolve(Jwt subject, String requesterClientId, String audience,
                                     Set<String> requestedScopes) {
        return resolve(subject, requesterClientId, audience, requestedScopes, null);
    }

    /** {@code delegationPurpose} (Phase 3.2) is accepted only on the customer-delegation profile. */
    @Transactional(readOnly = true)
    public ResolvedAuthority resolve(Jwt subject, String requesterClientId, String audience,
                                     Set<String> requestedScopes, String delegationPurpose) {
        ResolvedAuthority resolved = resolveAny(subject, requesterClientId, audience, requestedScopes, delegationPurpose);
        if (delegationPurpose != null && resolved.profile() != Profile.CIAM_CUSTOMER) {
            fail(new OAuth2Error(OAuth2ErrorCodes.INVALID_REQUEST));
        }
        return resolved;
    }

    private ResolvedAuthority resolveAny(Jwt subject, String requesterClientId, String audience,
                                         Set<String> requestedScopes, String delegationPurpose) {
        String tenantId = required(subject, "tenant_id");
        TrustedExchangeBroker broker = brokers.findByOauthClientId(requesterClientId)
                .filter(value -> value.getStatus() == TrustedExchangeBroker.Status.ACTIVE)
                .orElse(null);
        if (broker != null) return resolveGateway(subject, broker, audience, requestedScopes);
        AgentWorkloadIdentity requester = activeWorkloadByClient(requesterClientId, tenantId);
        if (!exchanged(subject)) {
            return switch (required(subject, "identity_kind")) {
                case "customer" -> singleAudience(subject, TokenExchangeConstants.SUBJECT_AUDIENCE)
                        ? resolveCustomer(subject, requester, audience, requestedScopes, delegationPurpose)
                        : resolveCustomerSession(subject, requester, audience, requestedScopes);
                case "workforce" -> resolveWorkforce(subject, requester, audience, requestedScopes);
                case "workload" -> resolveAutonomousWorkload(subject, requester, audience, requestedScopes);
                default -> throw new OAuth2AuthenticationException(INVALID_GRANT);
            };
        }
        return resolveContinuation(subject, requester, audience, requestedScopes);
    }

    /** Decoder-time validation. This runs before requester-specific exchange resolution. */
    @Transactional(readOnly = true)
    public void requireValidNonCustomerSubject(Jwt subject) {
        requireCurrentInvocationContext(subject);
        String tenantId = required(subject, "tenant_id");
        String identityKind = required(subject, "identity_kind");
        if (!exchanged(subject)) {
            String clientId = required(subject, "client_id");
            var client = applications.activeAuthority(clientId)
                    .filter(value -> value.tenantId().equals(tenantId))
                    .orElseThrow(() -> new OAuth2AuthenticationException(INVALID_GRANT));
            if ("workforce".equals(identityKind)) {
                if (!client.workforceSignIn()
                        || !singleAudience(subject, client.audience())
                        || applicationAccess.decisionAuthority(tenantId, client.applicationId(), subject.getSubject()).isEmpty()) {
                    fail(INVALID_GRANT);
                }
                return;
            }
            if ("workload".equals(identityKind)) {
                if (client.clientType() != TenantApplicationClient.Type.CONFIDENTIAL_SERVICE
                        || !clientId.equals(subject.getSubject()) || !singleAudience(subject, client.audience())) {
                    fail(INVALID_GRANT);
                }
                activeWorkloadByClient(clientId, tenantId);
                return;
            }
            fail(INVALID_GRANT);
        }

        Actor current = currentActor(subject, tenantId);
        AgentWorkloadIdentity actor = requireActiveActor(current, tenantId);
        if (!Set.of("workforce", "workload", "customer").contains(identityKind)) fail(INVALID_GRANT);
        String tokenUse = required(subject, "token_use");
        String profile = required(subject, "authority_profile");
        if ("customer".equals(identityKind)) {
            // A customer chain exists only under the customer-session profile and while the customer is still active.
            if (Profile.CIAM_CUSTOMER.name().toLowerCase().equals(profile)) fail(INVALID_GRANT);
            requireActiveCustomer(tenantId, subject.getSubject());
        }
        if (TokenUse.EXCHANGE_SUBJECT.name().toLowerCase().equals(tokenUse)
                && Profile.CUSTOMER_SESSION.name().toLowerCase().equals(profile)) {
            if (!required(subject, "client_id").equals(actor.getOauthClientId())
                    || !singleAudience(subject, receivingAudience(actor))) fail(INVALID_GRANT);
            requireCustomerAuthority(subject, actor, subjectScopes(subject));
            return;
        }
        if (TokenUse.EXCHANGE_SUBJECT.name().toLowerCase().equals(tokenUse)
                && Profile.WORKFORCE.name().toLowerCase().equals(profile)) {
            if (!required(subject, "client_id").equals(actor.getOauthClientId())
                    || !singleAudience(subject, receivingAudience(actor))) fail(INVALID_GRANT);
            requireWorkforceAuthority(subject, actor, subjectScopes(subject));
            return;
        }
        if (TokenUse.GATEWAY_AUTHORIZATION.name().toLowerCase().equals(tokenUse)) {
            AgentExchangeRoute route = routeByAuthority(subject, tenantId);
            if (!Profile.WORKLOAD_CONTINUATION.name().toLowerCase().equals(profile)
                    || !required(subject, "client_id").equals(actor.getOauthClientId())
                    || route.getDestinationType() != AgentExchangeRoute.DestinationType.GATEWAY
                    || !route.getSourceWorkloadId().equals(actor.getId())
                    || !route.getAudience().equals(subject.getAudience().size() == 1
                    ? subject.getAudience().getFirst() : "")) fail(INVALID_GRANT);
            TrustedExchangeBroker broker = activeBrokerByAudience(tenantId, route.getAudience());
            requireScopeSubset(subjectScopes(subject), route.getAllowedScopes(),
                    confidentialAuthority(actor.getOauthClientId(), tenantId).scopes());
            return;
        }
        if (TokenUse.EXCHANGE_SUBJECT.name().toLowerCase().equals(tokenUse)) {
            TrustedExchangeBroker broker = activeBrokerByClient(tenantId, required(subject, "client_id"));
            if (brokerTargetAuthority(subject)) {
                TrustedExchangeBrokerTarget target = targetByAuthority(subject, tenantId, broker);
                requireGatewayEntryRoute(subject, actor, tenantId, broker);
                if (!Profile.GATEWAY_BACKEND.name().toLowerCase().equals(profile)
                        || target.getDestinationType() != AgentExchangeRoute.DestinationType.AGENT
                        || !singleAudience(subject, target.getAudience())) fail(INVALID_GRANT);
                AgentWorkloadIdentity destination = activeWorkload(tenantId, target.getDestinationWorkloadId());
                if (!receivingAudience(destination).equals(target.getAudience())) fail(INVALID_GRANT);
                requireScopeSubset(subjectScopes(subject), target.getAllowedScopes(),
                        confidentialAuthority(destination.getOauthClientId(), tenantId).scopes());
                return;
            }
            AgentExchangeRoute route = routeByAuthority(subject, tenantId);
            if (!Profile.GATEWAY_BACKEND.name().toLowerCase().equals(profile)
                    || route.getDestinationType() != AgentExchangeRoute.DestinationType.AGENT
                    || !route.getSourceWorkloadId().equals(actor.getId())
                    || !singleAudience(subject, route.getAudience())) fail(INVALID_GRANT);
            AgentWorkloadIdentity destination = activeWorkload(tenantId, route.getDestinationWorkloadId());
            if (!receivingAudience(destination).equals(route.getAudience())) fail(INVALID_GRANT);
            requireScopeSubset(subjectScopes(subject), route.getAllowedScopes(),
                    confidentialAuthority(destination.getOauthClientId(), tenantId).scopes());
            return;
        }
        // Direct CIAM delegated access and resource tokens are deliberately not transitive.
        fail(INVALID_GRANT);
    }

    private com.openwolf.iam.authority.approval.ActionApprovalService actionApprovals;

    @org.springframework.beans.factory.annotation.Autowired(required = false)
    void setActionApprovals(com.openwolf.iam.authority.approval.ActionApprovalService actionApprovals) {
        this.actionApprovals = actionApprovals;
    }

    private com.openwolf.iam.authority.standing.StandingGrantService standingGrants;
    private com.openwolf.iam.authority.standing.StandingGrantService.TaskBinding taskBinding;

    @org.springframework.beans.factory.annotation.Autowired(required = false)
    void setStandingGrants(com.openwolf.iam.authority.standing.StandingGrantService standingGrants,
                           com.openwolf.iam.authority.task.DurableTaskService tasks) {
        this.standingGrants = standingGrants;
        this.taskBinding = tasks;
    }

    /** Introspection-time validation for non-CIAM exchange results. */
    @Transactional(readOnly = true)
    public void requireValidIssuedToken(Jwt token) {
        // Phase 3.3: standing-grant tokens are validated against the grant's current state, never by signature alone.
        if (com.openwolf.iam.authority.standing.StandingGrantService.PROFILE.equals(token.getClaimAsString("authority_profile"))) {
            if (standingGrants == null) fail(INVALID_GRANT);
            standingGrants.requireCurrent(token, taskBinding);
            return;
        }
        // Phase 3.8: approved-action tokens are valid only while their consumed approval stands.
        if (com.openwolf.iam.authority.approval.ActionApprovalService.PROFILE.equals(token.getClaimAsString("authority_profile"))) {
            if (actionApprovals == null) fail(INVALID_GRANT);
            actionApprovals.requireCurrent(token);
            return;
        }
        requireCurrentInvocationContext(token);
        if (TokenUse.DELEGATED_ACCESS.name().toLowerCase().equals(token.getClaimAsString("token_use"))
                && Profile.GATEWAY_BACKEND.name().toLowerCase().equals(token.getClaimAsString("authority_profile"))) {
            String tenantId = required(token, "tenant_id");
            if ("customer".equals(token.getClaimAsString("identity_kind"))) requireActiveCustomer(tenantId, token.getSubject());
            AgentWorkloadIdentity actor = requireActiveActor(currentActor(token, tenantId), tenantId);
            TrustedExchangeBroker broker = activeBrokerByClient(tenantId, required(token, "client_id"));
            if (brokerTargetAuthority(token)) {
                TrustedExchangeBrokerTarget target = targetByAuthority(token, tenantId, broker);
                requireGatewayEntryRoute(token, actor, tenantId, broker);
                if (target.getDestinationType() != AgentExchangeRoute.DestinationType.RESOURCE
                        || !singleAudience(token, target.getAudience())
                        || !target.getAllowedScopes().containsAll(subjectScopes(token))
                        || !applications.isActiveAudience(tenantId, target.getAudience())) fail(INVALID_GRANT);
                return;
            }
            AgentExchangeRoute route = routeByAuthority(token, tenantId);
            if (route.getDestinationType() != AgentExchangeRoute.DestinationType.RESOURCE
                    || !route.getSourceWorkloadId().equals(actor.getId())
                    || !singleAudience(token, route.getAudience())
                    || !route.getAllowedScopes().containsAll(subjectScopes(token))
                    || !applications.isActiveAudience(tenantId, route.getAudience())) fail(INVALID_GRANT);
            return;
        }
        if (TokenUse.DELEGATED_ACCESS.name().toLowerCase().equals(token.getClaimAsString("token_use"))
                && ("workforce".equals(token.getClaimAsString("authority_profile"))
                || "customer_session".equals(token.getClaimAsString("authority_profile")))) {
            String tenantId = required(token, "tenant_id");
            AgentWorkloadIdentity actor = requireActiveActor(actor(token), tenantId);
            AgentExchangeRoute route = routeByAuthority(token, tenantId);
            if (route.getDestinationType() != AgentExchangeRoute.DestinationType.RESOURCE
                    || !route.getSourceWorkloadId().equals(actor.getId())
                    || !required(token, "client_id").equals(actor.getOauthClientId())
                    || !singleAudience(token, route.getAudience())
                    || !applications.isActiveAudience(tenantId, route.getAudience())) fail(INVALID_GRANT);
            requireScopeSubset(subjectScopes(token), route.getAllowedScopes(),
                    confidentialAuthority(actor.getOauthClientId(), tenantId).scopes());
            if ("workforce".equals(token.getClaimAsString("authority_profile"))) {
                if (!"workforce".equals(required(token, "identity_kind"))) fail(INVALID_GRANT);
                var actorClient = confidentialAuthority(actor.getOauthClientId(), tenantId);
                var workforce = applicationAccess.decisionAuthority(tenantId, actorClient.applicationId(), token.getSubject())
                        .orElseThrow(() -> new OAuth2AuthenticationException(INVALID_GRANT));
                requireScopeSubset(subjectScopes(token), workforce.permissionEffects().keySet());
            } else {
                if (!"customer".equals(required(token, "identity_kind"))) fail(INVALID_GRANT);
                requireActiveCustomer(tenantId, token.getSubject());
            }
            return;
        }
        requireValidNonCustomerSubject(token);
    }

    private com.openwolf.iam.invocation.InvocationContextService invocationContexts;

    @org.springframework.beans.factory.annotation.Autowired(required = false)
    void setInvocationContexts(com.openwolf.iam.invocation.InvocationContextService invocationContexts) {
        this.invocationContexts = invocationContexts;
    }

    /** A context-bound token is valid only while its invocation context is current (Phase 2.6, fail closed). */
    private void requireCurrentInvocationContext(Jwt token) {
        if (!token.getClaims().containsKey(com.openwolf.iam.invocation.InvocationContextService.CLAIM_CONTEXT)) return;
        if (invocationContexts == null) fail(INVALID_GRANT);
        invocationContexts.requireCurrent(token);
    }

    /** The active trusted broker registered for an authenticated client (establishment provenance). */
    @Transactional(readOnly = true)
    public TrustedExchangeBroker activeBroker(String tenantId, String clientId) {
        return activeBrokerByClient(tenantId, clientId);
    }

    private ResolvedAuthority resolveCustomer(Jwt subject, AgentWorkloadIdentity requester, String audience,
                                              Set<String> scopes, String delegationPurpose) {
        if (!singleAudience(subject, TokenExchangeConstants.SUBJECT_AUDIENCE)) fail(INVALID_GRANT);
        var actorClient = confidentialAuthority(requester.getOauthClientId(), requester.getTenantId());
        if (!actorClient.audience().equals(audience)) fail(INVALID_TARGET);
        requireScopeSubset(scopes, subjectScopes(subject), actorClient.scopes());
        String subjectClientId = required(subject, "client_id");
        applications.activeAuthority(subjectClientId)
                .filter(value -> value.clientType() == TenantApplicationClient.Type.PUBLIC_BROWSER)
                .filter(value -> value.tenantId().equals(requester.getTenantId()))
                .orElseThrow(() -> new OAuth2AuthenticationException(INVALID_GRANT));
        UUID customerId;
        try { customerId = UUID.fromString(subject.getSubject()); }
        catch (RuntimeException invalid) { throw new OAuth2AuthenticationException(INVALID_GRANT); }
        CiamDelegationAuthorityService.AuthorizedDelegation approved;
        try {
            approved = customerAuthority.requireAuthorized(requester.getTenantId(), customerId,
                    requester.getOauthClientId(), audience, scopes, delegationPurpose, null);
        } catch (RuntimeException denied) {
            throw new OAuth2AuthenticationException(INVALID_GRANT);
        }
        if (!approved.workloadId().equals(requester.getId())) fail(INVALID_GRANT);
        return new ResolvedAuthority(Profile.CIAM_CUSTOMER, TokenUse.DELEGATED_ACCESS, subject,
                requester.getTenantId(), audience, scopes, "customer", approved.purpose(),
                approved.grantId().toString(), approved.grantId().toString(), requester, approved.expiresAt(), null, null);
    }

    private ResolvedAuthority resolveWorkforce(Jwt subject, AgentWorkloadIdentity requester, String audience,
                                               Set<String> scopes) {
        var actorClient = confidentialAuthority(requester.getOauthClientId(), requester.getTenantId());
        String sourceClientId = required(subject, "client_id");
        var sourceClient = applications.activeAuthority(sourceClientId)
                .filter(TenantApplicationService.ClientAuthority::workforceSignIn)
                .filter(value -> value.tenantId().equals(requester.getTenantId()))
                .orElseThrow(() -> new OAuth2AuthenticationException(INVALID_GRANT));
        if (!singleAudience(subject, sourceClient.audience())) fail(INVALID_GRANT);
        // A human token from another application cannot borrow this workload's entitlements.
        if (!sourceClient.applicationId().equals(actorClient.applicationId())) fail(INVALID_GRANT);
        var workforce = applicationAccess.decisionAuthority(requester.getTenantId(),
                        actorClient.applicationId(), subject.getSubject())
                .orElseThrow(() -> new OAuth2AuthenticationException(INVALID_GRANT));
        Set<String> permitted = workforce.permissionEffects().keySet();
        if (!actorClient.audience().equals(audience)) {
            return resolvePersonResource(Profile.WORKFORCE, subject, requester, audience, scopes,
                    () -> requireScopeSubset(scopes, subjectScopes(subject), actorClient.scopes(), permitted));
        }
        requireScopeSubset(scopes, subjectScopes(subject), actorClient.scopes(), permitted);
        String authorityId = "workforce:" + actorClient.applicationId() + ":"
                + subject.getSubject() + ":" + workforce.entitlementRevision();
        return new ResolvedAuthority(Profile.WORKFORCE, TokenUse.EXCHANGE_SUBJECT, subject,
                requester.getTenantId(), audience, scopes, "workforce",
                "Workforce authority delegated to " + requester.getWorkloadRef(), authorityId,
                null, requester, subject.getExpiresAt(), null, null);
    }

    private ResolvedAuthority resolveAutonomousWorkload(Jwt subject, AgentWorkloadIdentity requester,
                                                        String audience, Set<String> scopes) {
        if (!requester.getOauthClientId().equals(required(subject, "client_id"))
                || !requester.getOauthClientId().equals(subject.getSubject())) fail(INVALID_GRANT);
        String receivingAudience = receivingAudience(requester);
        if (!singleAudience(subject, receivingAudience)) fail(INVALID_GRANT);
        AgentExchangeRoute route = activeRoute(requester.getTenantId(), requester.getId(), audience,
                AgentExchangeRoute.DestinationType.GATEWAY, scopes);
        TrustedExchangeBroker broker = activeBrokerByAudience(requester.getTenantId(), audience);
        requireScopeSubset(scopes, subjectScopes(subject), route.getAllowedScopes());
        return routeAuthority(Profile.WORKLOAD_CONTINUATION, TokenUse.GATEWAY_AUTHORIZATION,
                subject, requester, route, "workload", scopes);
    }

    private ResolvedAuthority resolveContinuation(Jwt subject, AgentWorkloadIdentity requester,
                                                  String audience, Set<String> scopes) {
        if (!TokenUse.EXCHANGE_SUBJECT.name().toLowerCase().equals(required(subject, "token_use"))) {
            fail(INVALID_GRANT);
        }
        if (!singleAudience(subject, receivingAudience(requester))) fail(INVALID_GRANT);
        String profile = required(subject, "authority_profile");
        if (Profile.WORKFORCE.name().toLowerCase().equals(profile)
                || Profile.CUSTOMER_SESSION.name().toLowerCase().equals(profile)) {
            Profile personProfile = Profile.WORKFORCE.name().toLowerCase().equals(profile)
                    ? Profile.WORKFORCE : Profile.CUSTOMER_SESSION;
            AgentWorkloadIdentity initial = requireActiveActor(actor(subject), requester.getTenantId());
            if (!initial.getId().equals(requester.getId())) fail(INVALID_GRANT);
            if (personProfile == Profile.WORKFORCE) requireWorkforceAuthority(subject, requester, scopes);
            else requireCustomerAuthority(subject, requester, scopes);
            AgentExchangeRoute outbound = activeRoute(requester.getTenantId(), requester.getId(), audience, null, scopes, true);
            try {
                requireScopeSubset(scopes, subjectScopes(subject), outbound.getAllowedScopes());
                if (outbound.getDestinationType() == AgentExchangeRoute.DestinationType.RESOURCE) {
                    return personResourceAuthority(personProfile, subject, requester, outbound, scopes);
                }
                if (outbound.getDestinationType() != AgentExchangeRoute.DestinationType.GATEWAY) fail(INVALID_TARGET);
                activeBrokerByAudience(requester.getTenantId(), audience);
                return routeAuthority(Profile.WORKLOAD_CONTINUATION, TokenUse.GATEWAY_AUTHORIZATION,
                        subject, requester, outbound, personProfile == Profile.CUSTOMER_SESSION
                                ? "customer" : required(subject, "identity_kind"), scopes);
            } catch (OAuth2AuthenticationException denied) {
                throw routeDenied(denied, outbound);
            }
        }
        if (!Profile.GATEWAY_BACKEND.name().toLowerCase().equals(profile)) fail(INVALID_GRANT);
        Actor previous = currentActor(subject, requester.getTenantId());
        if (brokerTargetAuthority(subject)) {
            TrustedExchangeBroker broker = activeBrokerByClient(requester.getTenantId(), required(subject, "client_id"));
            TrustedExchangeBrokerTarget inbound = targetByAuthority(subject, requester.getTenantId(), broker);
            requireGatewayEntryRoute(subject, requireActiveActor(previous, requester.getTenantId()),
                    requester.getTenantId(), broker);
            if (inbound.getDestinationType() != AgentExchangeRoute.DestinationType.AGENT
                    || !requester.getId().equals(inbound.getDestinationWorkloadId())
                    || !inbound.getAudience().equals(receivingAudience(requester))) fail(INVALID_GRANT);
            requireActiveActor(previous, requester.getTenantId());
            AgentExchangeRoute outbound = activeRoute(requester.getTenantId(), requester.getId(), audience,
                    AgentExchangeRoute.DestinationType.GATEWAY, scopes);
            TrustedExchangeBroker outboundBroker = activeBrokerByAudience(requester.getTenantId(), audience);
            requireScopeSubset(scopes, subjectScopes(subject), outbound.getAllowedScopes());
            return routeAuthority(Profile.WORKLOAD_CONTINUATION, TokenUse.GATEWAY_AUTHORIZATION,
                    subject, requester, outbound, required(subject, "identity_kind"), scopes);
        }
        AgentExchangeRoute inbound = routeByAuthority(subject, requester.getTenantId());
        if (inbound.getDestinationType() != AgentExchangeRoute.DestinationType.AGENT
                || !requester.getId().equals(inbound.getDestinationWorkloadId())
                || !previous.workloadId().equals(inbound.getSourceWorkloadId())
                || !inbound.getAudience().equals(receivingAudience(requester))) fail(INVALID_GRANT);
        requireActiveActor(previous, requester.getTenantId());
        AgentExchangeRoute outbound = activeRoute(requester.getTenantId(), requester.getId(), audience,
                AgentExchangeRoute.DestinationType.GATEWAY, scopes);
        TrustedExchangeBroker broker = activeBrokerByAudience(requester.getTenantId(), audience);
        requireScopeSubset(scopes, subjectScopes(subject), outbound.getAllowedScopes());
        return routeAuthority(Profile.WORKLOAD_CONTINUATION, TokenUse.GATEWAY_AUTHORIZATION,
                subject, requester, outbound, required(subject, "identity_kind"), scopes);
    }

    /**
     * Customer browser login → a workload of the same application. The authority is the customer's own sign-in to that
     * application's customer-facing client (with the scopes the customer granted there), re-checked live: the client
     * and application are active, the customer is ACTIVE at the signed-in token version. Scopes never widen beyond the
     * customer's token and the workload client's registration.
     */
    private ResolvedAuthority resolveCustomerSession(Jwt subject, AgentWorkloadIdentity requester, String audience,
                                                     Set<String> scopes) {
        var actorClient = confidentialAuthority(requester.getOauthClientId(), requester.getTenantId());
        String sourceClientId = required(subject, "client_id");
        var sourceClient = applications.activeAuthority(sourceClientId)
                .filter(TenantApplicationService.ClientAuthority::customerSignIn)
                .filter(value -> value.tenantId().equals(requester.getTenantId()))
                .orElseThrow(() -> new OAuth2AuthenticationException(INVALID_GRANT));
        if (!singleAudience(subject, sourceClient.audience())) fail(INVALID_GRANT);
        // A customer token from another application cannot borrow this workload's registration.
        if (!sourceClient.applicationId().equals(actorClient.applicationId())) fail(INVALID_GRANT);
        long version = requireCurrentCustomerVersion(requester.getTenantId(), subject);
        if (!actorClient.audience().equals(audience)) {
            return resolvePersonResource(Profile.CUSTOMER_SESSION, subject, requester, audience, scopes,
                    () -> requireScopeSubset(scopes, subjectScopes(subject), actorClient.scopes(), sourceClient.scopes()));
        }
        requireScopeSubset(scopes, subjectScopes(subject), actorClient.scopes(), sourceClient.scopes());
        String authorityId = customerAuthorityId(actorClient.applicationId(), subject.getSubject(), version);
        return new ResolvedAuthority(Profile.CUSTOMER_SESSION, TokenUse.EXCHANGE_SUBJECT, subject,
                requester.getTenantId(), audience, scopes, "customer",
                "Customer authority delegated to " + requester.getWorkloadRef(), authorityId,
                null, requester, subject.getExpiresAt(), null, null);
    }

    /** The exchanged customer token's authority is still current for its acting workload. */
    private void requireCustomerAuthority(Jwt subject, AgentWorkloadIdentity requester, Set<String> scopes) {
        var actorClient = confidentialAuthority(requester.getOauthClientId(), requester.getTenantId());
        requireScopeSubset(scopes, actorClient.scopes());
        String authorityId = required(subject, "authority_id");
        String prefix = "customer:" + actorClient.applicationId() + ":" + subject.getSubject() + ":";
        if (!authorityId.startsWith(prefix)) fail(INVALID_GRANT);
        long version;
        try { version = Long.parseLong(authorityId.substring(prefix.length())); }
        catch (NumberFormatException malformed) { throw new OAuth2AuthenticationException(INVALID_GRANT); }
        if (customers == null) fail(INVALID_GRANT);
        UUID customerId;
        try { customerId = UUID.fromString(subject.getSubject()); }
        catch (RuntimeException invalid) { throw new OAuth2AuthenticationException(INVALID_GRANT); }
        customers.findByTenantIdAndId(requester.getTenantId(), customerId)
                .filter(value -> value.getStatus() == com.openwolf.iam.entity.CustomerIdentity.Status.ACTIVE)
                .filter(value -> value.getTokenVersion() == version)
                .orElseThrow(() -> new OAuth2AuthenticationException(INVALID_GRANT));
    }

    private long requireCurrentCustomerVersion(String tenantId, Jwt subject) {
        Number tokenVersion = subject.getClaim("token_version");
        if (tokenVersion == null || customers == null) fail(INVALID_GRANT);
        UUID customerId;
        try { customerId = UUID.fromString(subject.getSubject()); }
        catch (RuntimeException invalid) { throw new OAuth2AuthenticationException(INVALID_GRANT); }
        return customers.findByTenantIdAndId(tenantId, customerId)
                .filter(value -> value.getStatus() == com.openwolf.iam.entity.CustomerIdentity.Status.ACTIVE)
                .filter(value -> value.getTokenVersion() == tokenVersion.longValue())
                .map(com.openwolf.iam.entity.CustomerIdentity::getTokenVersion)
                .orElseThrow(() -> new OAuth2AuthenticationException(INVALID_GRANT));
    }

    private void requireActiveCustomer(String tenantId, String subject) {
        if (customers == null) fail(INVALID_GRANT);
        UUID customerId;
        try { customerId = UUID.fromString(subject); }
        catch (RuntimeException invalid) { throw new OAuth2AuthenticationException(INVALID_GRANT); }
        customers.findByTenantIdAndId(tenantId, customerId)
                .filter(value -> value.getStatus() == com.openwolf.iam.entity.CustomerIdentity.Status.ACTIVE)
                .orElseThrow(() -> new OAuth2AuthenticationException(INVALID_GRANT));
    }

    private static String customerAuthorityId(UUID applicationId, String customerId, long version) {
        return "customer:" + applicationId + ":" + customerId + ":" + version;
    }

    private com.openwolf.iam.repository.CustomerIdentityRepository customers;

    @org.springframework.beans.factory.annotation.Autowired(required = false)
    void setCustomers(com.openwolf.iam.repository.CustomerIdentityRepository customers) {
        this.customers = customers;
    }

    private ApplicationAccessService.DecisionAuthority requireWorkforceAuthority(
            Jwt subject, AgentWorkloadIdentity requester, Set<String> scopes) {
        var actorClient = confidentialAuthority(requester.getOauthClientId(), requester.getTenantId());
        var workforce = applicationAccess.decisionAuthority(requester.getTenantId(),
                        actorClient.applicationId(), subject.getSubject())
                .orElseThrow(() -> new OAuth2AuthenticationException(INVALID_GRANT));
        requireScopeSubset(scopes, workforce.permissionEffects().keySet(), actorClient.scopes());
        String expected = "workforce:" + actorClient.applicationId() + ":"
                + subject.getSubject() + ":" + workforce.entitlementRevision();
        if (!expected.equals(required(subject, "authority_id"))) fail(INVALID_GRANT);
        return workforce;
    }

    private ResolvedAuthority resolveGateway(Jwt subject, TrustedExchangeBroker broker,
                                             String audience, Set<String> scopes) {
        if (!broker.getTenantId().equals(required(subject, "tenant_id"))
                || !TokenUse.GATEWAY_AUTHORIZATION.name().toLowerCase().equals(required(subject, "token_use"))
                || !Profile.WORKLOAD_CONTINUATION.name().toLowerCase().equals(required(subject, "authority_profile"))
                || !singleAudience(subject, broker.getGatewayAudience())) fail(INVALID_GRANT);
        AgentWorkloadIdentity source = requireActiveActor(currentActor(subject, broker.getTenantId()), broker.getTenantId());
        if ("customer".equals(subject.getClaimAsString("identity_kind"))) {
            requireActiveCustomer(broker.getTenantId(), subject.getSubject());
        }
        if (!source.getOauthClientId().equals(required(subject, "client_id"))) fail(INVALID_GRANT);
        AgentExchangeRoute gatewayRoute = routeByAuthority(subject, broker.getTenantId());
        if (gatewayRoute.getDestinationType() != AgentExchangeRoute.DestinationType.GATEWAY
                || !source.getId().equals(gatewayRoute.getSourceWorkloadId())
                || !broker.getGatewayAudience().equals(gatewayRoute.getAudience())) fail(INVALID_GRANT);
        var brokerTarget = brokerTargets.resolve(broker.getTenantId(), broker.getId(), audience);
        if (brokerTarget.isPresent()) {
            TrustedExchangeBrokerTarget target = brokerTarget.get();
            if (target.getDestinationType() == AgentExchangeRoute.DestinationType.AGENT) {
                AgentWorkloadIdentity destination = activeWorkload(broker.getTenantId(), target.getDestinationWorkloadId());
                if (!receivingAudience(destination).equals(audience)) fail(INVALID_TARGET);
                requireScopeSubset(scopes, confidentialAuthority(destination.getOauthClientId(), broker.getTenantId()).scopes());
            } else if (target.getDestinationType() != AgentExchangeRoute.DestinationType.RESOURCE
                    || !applications.isActiveAudience(broker.getTenantId(), audience)) fail(INVALID_TARGET);
            requireScopeSubset(scopes, subjectScopes(subject), target.getAllowedScopes());
            TokenUse use = target.getDestinationType() == AgentExchangeRoute.DestinationType.AGENT
                    ? TokenUse.EXCHANGE_SUBJECT : TokenUse.DELEGATED_ACCESS;
            return new ResolvedAuthority(Profile.GATEWAY_BACKEND, use, subject, broker.getTenantId(),
                    audience, scopes, required(subject, "identity_kind"), target.getPurpose(),
                    "broker-target:" + target.getId(), null, source, subject.getExpiresAt(),
                    null, target.getDestinationType());
        }
        AgentExchangeRoute target = activeRoute(broker.getTenantId(), source.getId(), audience, null, scopes);
        if (target.getDestinationType() == AgentExchangeRoute.DestinationType.GATEWAY) fail(INVALID_TARGET);
        if (target.getDestinationType() == AgentExchangeRoute.DestinationType.AGENT) {
            AgentWorkloadIdentity destination = activeWorkload(broker.getTenantId(), target.getDestinationWorkloadId());
            if (!receivingAudience(destination).equals(audience)) fail(INVALID_TARGET);
            requireScopeSubset(scopes, confidentialAuthority(destination.getOauthClientId(), broker.getTenantId()).scopes());
        } else if (!applications.isActiveAudience(broker.getTenantId(), target.getAudience())) {
            fail(INVALID_TARGET);
        }
        requireScopeSubset(scopes, subjectScopes(subject), target.getAllowedScopes());
        TokenUse use = target.getDestinationType() == AgentExchangeRoute.DestinationType.AGENT
                ? TokenUse.EXCHANGE_SUBJECT : TokenUse.DELEGATED_ACCESS;
        return routeAuthority(Profile.GATEWAY_BACKEND, use, subject, source, target,
                required(subject, "identity_kind"), scopes);
    }

    private ResolvedAuthority resolvePersonResource(Profile profile, Jwt subject, AgentWorkloadIdentity requester,
                                                     String audience, Set<String> scopes, Runnable checkScopes) {
        AgentExchangeRoute route = activeRoute(requester.getTenantId(), requester.getId(), audience,
                AgentExchangeRoute.DestinationType.RESOURCE, scopes, true);
        try {
            checkScopes.run();
            return personResourceAuthority(profile, subject, requester, route, scopes);
        } catch (OAuth2AuthenticationException denied) {
            throw routeDenied(denied, route);
        }
    }

    private ResolvedAuthority personResourceAuthority(Profile profile, Jwt subject, AgentWorkloadIdentity requester,
                                                       AgentExchangeRoute route, Set<String> scopes) {
        if (!applications.isActiveAudience(requester.getTenantId(), route.getAudience())) fail(INVALID_TARGET);
        requireScopeSubset(scopes, route.getAllowedScopes());
        return routeAuthority(profile, TokenUse.DELEGATED_ACCESS, subject, requester, route,
                required(subject, "identity_kind"), scopes);
    }

    private static RouteDenied routeDenied(OAuth2AuthenticationException denied, AgentExchangeRoute route) {
        return new RouteDenied(denied.getError(), route.getId().toString(), route.getDestinationType());
    }

    private ResolvedAuthority routeAuthority(Profile profile, TokenUse tokenUse, Jwt subject,
                                             AgentWorkloadIdentity actor, AgentExchangeRoute route,
                                             String identityKind, Set<String> scopes) {
        Instant expiry = route.getExpiresAt().isBefore(subject.getExpiresAt()) ? route.getExpiresAt() : subject.getExpiresAt();
        return new ResolvedAuthority(profile, tokenUse, subject, actor.getTenantId(), route.getAudience(),
                scopes, identityKind, route.getPurpose(), route.getId().toString(), null,
                actor, expiry, route.getId().toString(), route.getDestinationType());
    }

    private AgentExchangeRoute activeRoute(String tenantId, UUID sourceId, String audience,
                                           AgentExchangeRoute.DestinationType type, Set<String> requested) {
        return activeRoute(tenantId, sourceId, audience, type, requested, false);
    }

    private AgentExchangeRoute activeRoute(String tenantId, UUID sourceId, String audience,
                                           AgentExchangeRoute.DestinationType type, Set<String> requested,
                                           boolean resourceScopeError) {
        AgentExchangeRoute match = null;
        AgentExchangeRoute scopeDenied = null;
        for (AgentExchangeRoute route : routes.findByTenantIdAndSourceWorkloadIdAndAudienceAndStatus(
                tenantId, sourceId, audience, AgentExchangeRoute.Status.ACTIVE)) {
            if (!route.usableAt(clock.instant()) || (type != null && route.getDestinationType() != type)) continue;
            if (!route.getAllowedScopes().containsAll(requested)) {
                if (resourceScopeError && route.getDestinationType() == AgentExchangeRoute.DestinationType.RESOURCE) scopeDenied = route;
                continue;
            }
            if (match != null) throw new RouteDenied(INVALID_GRANT, null,
                    match.getDestinationType() == route.getDestinationType() ? route.getDestinationType() : null);
            match = route;
        }
        if (match == null) {
            if (scopeDenied != null) throw routeDenied(new OAuth2AuthenticationException(INVALID_SCOPE), scopeDenied);
            throw new RouteDenied(INVALID_TARGET, null, type);
        }
        return match;
    }

    private AgentExchangeRoute routeByAuthority(Jwt subject, String tenantId) {
        UUID routeId;
        try { routeId = UUID.fromString(required(subject, "authority_id")); }
        catch (RuntimeException invalid) { throw new OAuth2AuthenticationException(INVALID_GRANT); }
        return routes.findByTenantIdAndId(tenantId, routeId)
                .filter(route -> route.usableAt(clock.instant()))
                .orElseThrow(() -> new OAuth2AuthenticationException(INVALID_GRANT));
    }

    private static boolean brokerTargetAuthority(Jwt token) {
        return token.getClaimAsString("authority_id") != null
                && token.getClaimAsString("authority_id").startsWith("broker-target:");
    }

    private TrustedExchangeBrokerTarget targetByAuthority(Jwt token, String tenantId, TrustedExchangeBroker broker) {
        if (brokerTargets == null || !brokerTargetAuthority(token)) fail(INVALID_GRANT);
        try {
            return brokerTargets.requireActive(tenantId, broker.getId(),
                    UUID.fromString(required(token, "authority_id").substring("broker-target:".length())));
        } catch (IllegalArgumentException invalid) {
            throw new OAuth2AuthenticationException(INVALID_GRANT);
        }
    }

    private void requireGatewayEntryRoute(Jwt token, AgentWorkloadIdentity source,
                                          String tenantId, TrustedExchangeBroker broker) {
        UUID routeId;
        try { routeId = UUID.fromString(required(token, "source_gateway_route_id")); }
        catch (IllegalArgumentException invalid) { throw new OAuth2AuthenticationException(INVALID_GRANT); }
        AgentExchangeRoute route = routes.findByTenantIdAndId(tenantId, routeId)
                .filter(value -> value.usableAt(clock.instant()))
                .orElseThrow(() -> new OAuth2AuthenticationException(INVALID_GRANT));
        if (route.getDestinationType() != AgentExchangeRoute.DestinationType.GATEWAY
                || !route.getSourceWorkloadId().equals(source.getId())
                || !route.getAudience().equals(broker.getGatewayAudience())
                || !route.getAllowedScopes().containsAll(subjectScopes(token))) fail(INVALID_GRANT);
    }

    private AgentWorkloadIdentity requireActiveActor(Actor actor, String tenantId) {
        AgentWorkloadIdentity workload;
        try {
            workload = activeWorkload(tenantId, actor.workloadId());
        } catch (EntityNotFoundException unknownActor) {
            throw new OAuth2AuthenticationException(INVALID_GRANT);
        }
        if (!workload.getWorkloadRef().equals(actor.workloadRef())
                || !workload.getOauthClientId().equals(actor.clientId())) fail(INVALID_GRANT);
        // Phase 0.5 freshness: workload authority is re-evaluated from current state at every exchange and
        // introspection, including the OAuth client that authenticates the workload (disable = authority withdrawn).
        if (applications.activeAuthority(workload.getOauthClientId())
                .filter(value -> value.clientType() == TenantApplicationClient.Type.CONFIDENTIAL_SERVICE)
                .filter(value -> value.tenantId().equals(tenantId)).isEmpty()) fail(INVALID_GRANT);
        return workload;
    }

    /**
     * An Axiom exchange result (it carries {@code token_use}; an actor alone also counts). A sign-in or client-credentials
     * token has neither. The exchange result of a service acting only for itself has no {@code act}, so {@code act}
     * presence is not the marker.
     */
    private static boolean exchanged(Jwt token) {
        return token.getClaims().containsKey("act") || token.getClaims().containsKey("token_use");
    }

    /**
     * The current actor of an exchanged token. With {@code act}: its outermost (top-level) members. Without one (a
     * service acting only for itself, RFC 8693 section 4.1): the subject workload, bound by verified state, never by a
     * self-referential claim: for route authority, the still-usable route's registered source workload; for broker-target
     * authority, the registered workload named by signed {@code sub} and pinned by signed {@code source_workload_id}.
     * Callers re-check the workload and its client as active ({@link #requireActiveActor}), plus route or target authority.
     */
    private Actor currentActor(Jwt token, String tenantId) {
        if (token.getClaims().containsKey("act")) return actor(token);
        if (!"workload".equals(token.getClaimAsString("identity_kind"))
                || !token.getClaims().containsKey("token_use")) fail(INVALID_GRANT);
        if (brokerTargetAuthority(token)) {
            TrustedExchangeBroker broker = activeBrokerByClient(tenantId, required(token, "client_id"));
            targetByAuthority(token, tenantId, broker);
            AgentWorkloadIdentity source = activeWorkloadByClient(token.getSubject(), tenantId);
            if (!source.getId().toString().equals(required(token, "source_workload_id"))) fail(INVALID_GRANT);
            return new Actor(source.getId(), source.getWorkloadRef(), source.getOauthClientId());
        }
        AgentExchangeRoute route = routeByAuthority(token, tenantId);
        AgentWorkloadIdentity source;
        try {
            source = activeWorkload(tenantId, route.getSourceWorkloadId());
        } catch (EntityNotFoundException unknownSource) {
            throw new OAuth2AuthenticationException(INVALID_GRANT);
        }
        if (!source.getOauthClientId().equals(token.getSubject())) fail(INVALID_GRANT);
        return new Actor(source.getId(), source.getWorkloadRef(), source.getOauthClientId());
    }

    private Actor actor(Jwt subject) {
        Object raw = subject.getClaims().get("act");
        if (!(raw instanceof Map<?, ?> value)) throw new OAuth2AuthenticationException(INVALID_GRANT);
        try {
            Object rawSubject = value.get("sub");
            Object rawClient = value.get("client_id");
            if (!(rawSubject instanceof String) || ((String) rawSubject).isBlank()
                    || !(rawClient instanceof String) || ((String) rawClient).isBlank()) fail(INVALID_GRANT);
            String workloadRef = (String) rawSubject;
            String clientId = (String) rawClient;
            UUID workloadId = UUID.fromString(String.valueOf(value.get("workload_id")));
            return new Actor(workloadId, workloadRef, clientId);
        } catch (RuntimeException invalid) {
            throw new OAuth2AuthenticationException(INVALID_GRANT);
        }
    }

    private AgentExchangeRouteResponse response(AgentExchangeRoute value) {
        return new AgentExchangeRouteResponse(value.getId(), value.getSourceWorkloadId(),
                value.getDestinationType(), value.getDestinationWorkloadId(), value.getAudience(),
                value.getAllowedScopes(), value.getPurpose(), value.getStatus(), value.getCreatedAt(),
                value.getExpiresAt(), value.getRevokedAt(), value.getRevision());
    }

    private static TrustedBrokerResponse response(TrustedExchangeBroker value) {
        return new TrustedBrokerResponse(value.getId(), value.getOauthClientId(), value.getGatewayAudience(),
                value.getAllowedScopes(), value.getStatus(), value.getCreatedAt(), value.getRevokedAt(),
                value.getRevision());
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

    private AgentWorkloadIdentity activeWorkloadByClient(String clientId, String tenantId) {
        return workloads.findByOauthClientId(clientId)
                .filter(value -> value.getTenantId().equals(tenantId))
                .filter(this::usable)
                .orElseThrow(() -> new OAuth2AuthenticationException(UNAUTHORIZED_CLIENT));
    }

    private AgentWorkloadIdentity activeWorkload(String tenantId, UUID id) {
        return workloads.findByTenantIdAndId(tenantId, id)
                .filter(this::usable)
                .orElseThrow(() -> EntityNotFoundException.forId("Agent workload identity", id));
    }

    private String receivingAudience(AgentWorkloadIdentity workload) {
        return confidentialAuthority(workload.getOauthClientId(), workload.getTenantId()).audience();
    }

    private TenantApplicationService.ClientAuthority confidentialAuthority(String clientId, String tenantId) {
        return applications.activeAuthority(clientId)
                .filter(value -> value.clientType() == TenantApplicationClient.Type.CONFIDENTIAL_SERVICE)
                .filter(value -> value.tenantId().equals(tenantId))
                .orElseThrow(() -> new OAuth2AuthenticationException(UNAUTHORIZED_CLIENT));
    }

    private TrustedExchangeBroker activeBrokerByAudience(String tenantId, String audience) {
        return brokers.findByTenantIdAndGatewayAudience(tenantId, audience)
                .filter(value -> value.getStatus() == TrustedExchangeBroker.Status.ACTIVE)
                .orElseThrow(() -> new OAuth2AuthenticationException(INVALID_TARGET));
    }

    private TrustedExchangeBroker activeBrokerByClient(String tenantId, String clientId) {
        TrustedExchangeBroker broker = brokers.findByTenantIdAndOauthClientId(tenantId, clientId)
                .filter(value -> value.getStatus() == TrustedExchangeBroker.Status.ACTIVE)
                .orElseThrow(() -> new OAuth2AuthenticationException(INVALID_GRANT));
        // A broker-issued token stays valid only while the broker's own OAuth client is active (Phase 0.5).
        if (applications.activeAuthority(clientId).filter(value -> value.tenantId().equals(tenantId)).isEmpty()) {
            fail(INVALID_GRANT);
        }
        return broker;
    }

    private TreeSet<String> approvedScopes(String tenantId, Collection<String> values) {
        TreeSet<String> scopes = new TreeSet<>();
        for (String value : values) {
            String scope = value.trim();
            if (scope.isBlank() || !businessScopes.isApproved(tenantId, scope)) {
                throw new IllegalArgumentException("exchange scopes must be deployment-approved business scopes");
            }
            scopes.add(scope);
        }
        if (scopes.isEmpty()) throw new IllegalArgumentException("exchange scopes are required");
        return scopes;
    }

    @SafeVarargs
    private static void requireScopeSubset(Set<String> requested, Collection<String>... authorities) {
        for (Collection<String> authority : authorities) {
            if (!authority.containsAll(requested)) fail(INVALID_SCOPE);
        }
    }

    private static boolean singleAudience(Jwt jwt, String expected) {
        return jwt.getAudience() != null && jwt.getAudience().size() == 1 && expected.equals(jwt.getAudience().getFirst());
    }

    private static String required(Jwt jwt, String claim) {
        String value = jwt.getClaimAsString(claim);
        if (value == null || value.isBlank()) fail(INVALID_GRANT);
        return value;
    }

    private static Set<String> subjectScopes(Jwt jwt) {
        Object raw = jwt.getClaims().get("scope");
        Set<String> result = new LinkedHashSet<>();
        if (raw instanceof String value) {
            for (String scope : value.trim().split("\\s+")) if (!scope.isBlank()) result.add(scope);
        } else if (raw instanceof Collection<?> values) {
            values.forEach(value -> result.add(String.valueOf(value)));
        }
        if (result.isEmpty()) fail(INVALID_SCOPE);
        return result;
    }

    private static void fail(OAuth2Error error) { throw new OAuth2AuthenticationException(error); }

    private record Actor(UUID workloadId, String workloadRef, String clientId) {}
}
