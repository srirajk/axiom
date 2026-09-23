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

    public enum Profile { CIAM_CUSTOMER, WORKFORCE, WORKLOAD_CONTINUATION, GATEWAY_BACKEND }
    public enum TokenUse { DELEGATED_ACCESS, EXCHANGE_SUBJECT, GATEWAY_AUTHORIZATION }

    public record ResolvedAuthority(
            Profile profile, TokenUse tokenUse, Jwt subject, String tenantId, String audience,
            Set<String> scopes, String identityKind, String purpose, String authorityId,
            String delegationId, AgentWorkloadIdentity actingWorkload, Instant authorityExpiresAt) {
        public ResolvedAuthority {
            scopes = Set.copyOf(scopes);
        }
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
        if (workloads.findByOauthClientId(clientId).isPresent()) {
            throw new ResourceConflictException("trusted Gateway broker cannot be an Agent workload");
        }
        if (brokers.findByTenantIdAndOauthClientId(tenantId, clientId).isPresent()) {
            throw new ResourceConflictException("trusted Gateway broker client already exists");
        }
        TreeSet<String> scopes = approvedScopes(request.scopes());
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
        TreeSet<String> scopes = approvedScopes(request.scopes());
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
                TrustedExchangeBroker broker = activeBrokerByAudience(tenantId, audience);
                if (!broker.getAllowedScopes().containsAll(scopes)) {
                    throw new IllegalArgumentException("Gateway route scopes exceed broker authority");
                }
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
                route.getId().toString(), Map.of("sourceWorkloadId", source.getId(),
                        "destinationType", route.getDestinationType(), "audience", audience,
                        "scopes", scopes, "expiresAt", request.expiresAt()), correlationId);
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
                routeId.toString(), Map.of("audience", route.getAudience()), correlationId);
        return response(route);
    }

    @Transactional(readOnly = true)
    public ResolvedAuthority resolve(Jwt subject, String requesterClientId, String audience,
                                     Set<String> requestedScopes) {
        String tenantId = required(subject, "tenant_id");
        TrustedExchangeBroker broker = brokers.findByOauthClientId(requesterClientId)
                .filter(value -> value.getStatus() == TrustedExchangeBroker.Status.ACTIVE)
                .orElse(null);
        if (broker != null) return resolveGateway(subject, broker, audience, requestedScopes);
        AgentWorkloadIdentity requester = activeWorkloadByClient(requesterClientId, tenantId);
        if (!subject.getClaims().containsKey("act")) {
            return switch (required(subject, "identity_kind")) {
                case "customer" -> resolveCustomer(subject, requester, audience, requestedScopes);
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
        String tenantId = required(subject, "tenant_id");
        String identityKind = required(subject, "identity_kind");
        if (!subject.getClaims().containsKey("act")) {
            String clientId = required(subject, "client_id");
            var client = applications.activeAuthority(clientId)
                    .filter(value -> value.tenantId().equals(tenantId))
                    .orElseThrow(() -> new OAuth2AuthenticationException(INVALID_GRANT));
            if ("workforce".equals(identityKind)) {
                if (client.clientType() != TenantApplicationClient.Type.PUBLIC_BROWSER
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

        Actor current = actor(subject);
        AgentWorkloadIdentity actor = requireActiveActor(current, tenantId);
        if (!Set.of("workforce", "workload").contains(identityKind)) fail(INVALID_GRANT);
        String tokenUse = required(subject, "token_use");
        String profile = required(subject, "authority_profile");
        if (TokenUse.EXCHANGE_SUBJECT.name().toLowerCase().equals(tokenUse)
                && Profile.WORKFORCE.name().toLowerCase().equals(profile)) {
            if (!required(subject, "client_id").equals(actor.getOauthClientId())
                    || !singleAudience(subject, receivingAudience(actor))) fail(INVALID_GRANT);
            requireWorkforceAuthority(subject, actor, subjectScopes(subject));
            return;
        }
        AgentExchangeRoute route = routeByAuthority(subject, tenantId);
        if (TokenUse.GATEWAY_AUTHORIZATION.name().toLowerCase().equals(tokenUse)) {
            if (!Profile.WORKLOAD_CONTINUATION.name().toLowerCase().equals(profile)
                    || !required(subject, "client_id").equals(actor.getOauthClientId())
                    || route.getDestinationType() != AgentExchangeRoute.DestinationType.GATEWAY
                    || !route.getSourceWorkloadId().equals(actor.getId())
                    || !route.getAudience().equals(subject.getAudience().size() == 1
                    ? subject.getAudience().getFirst() : "")) fail(INVALID_GRANT);
            TrustedExchangeBroker broker = activeBrokerByAudience(tenantId, route.getAudience());
            requireScopeSubset(subjectScopes(subject), route.getAllowedScopes(), broker.getAllowedScopes(),
                    confidentialAuthority(actor.getOauthClientId(), tenantId).scopes());
            return;
        }
        if (TokenUse.EXCHANGE_SUBJECT.name().toLowerCase().equals(tokenUse)) {
            TrustedExchangeBroker broker = activeBrokerByClient(tenantId, required(subject, "client_id"));
            if (!Profile.GATEWAY_BACKEND.name().toLowerCase().equals(profile)
                    || route.getDestinationType() != AgentExchangeRoute.DestinationType.AGENT
                    || !route.getSourceWorkloadId().equals(actor.getId())
                    || !singleAudience(subject, route.getAudience())) fail(INVALID_GRANT);
            AgentWorkloadIdentity destination = activeWorkload(tenantId, route.getDestinationWorkloadId());
            if (!receivingAudience(destination).equals(route.getAudience())) fail(INVALID_GRANT);
            requireScopeSubset(subjectScopes(subject), route.getAllowedScopes(), broker.getAllowedScopes(),
                    confidentialAuthority(destination.getOauthClientId(), tenantId).scopes());
            return;
        }
        // Direct CIAM delegated access and resource tokens are deliberately not transitive.
        fail(INVALID_GRANT);
    }

    /** Introspection-time validation for non-CIAM exchange results. */
    @Transactional(readOnly = true)
    public void requireValidIssuedToken(Jwt token) {
        if (TokenUse.DELEGATED_ACCESS.name().toLowerCase().equals(token.getClaimAsString("token_use"))
                && Profile.GATEWAY_BACKEND.name().toLowerCase().equals(token.getClaimAsString("authority_profile"))) {
            String tenantId = required(token, "tenant_id");
            AgentWorkloadIdentity actor = requireActiveActor(actor(token), tenantId);
            AgentExchangeRoute route = routeByAuthority(token, tenantId);
            if (route.getDestinationType() != AgentExchangeRoute.DestinationType.RESOURCE
                    || !route.getSourceWorkloadId().equals(actor.getId())
                    || !singleAudience(token, route.getAudience())
                    || !route.getAllowedScopes().containsAll(subjectScopes(token))
                    || !applications.isActiveAudience(tenantId, route.getAudience())) fail(INVALID_GRANT);
            TrustedExchangeBroker broker = activeBrokerByClient(tenantId, required(token, "client_id"));
            requireScopeSubset(subjectScopes(token), broker.getAllowedScopes());
            return;
        }
        requireValidNonCustomerSubject(token);
    }

    private ResolvedAuthority resolveCustomer(Jwt subject, AgentWorkloadIdentity requester, String audience,
                                              Set<String> scopes) {
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
                    requester.getOauthClientId(), audience, scopes);
        } catch (RuntimeException denied) {
            throw new OAuth2AuthenticationException(INVALID_GRANT);
        }
        if (!approved.workloadId().equals(requester.getId())) fail(INVALID_GRANT);
        return new ResolvedAuthority(Profile.CIAM_CUSTOMER, TokenUse.DELEGATED_ACCESS, subject,
                requester.getTenantId(), audience, scopes, "customer", approved.purpose(),
                approved.grantId().toString(), approved.grantId().toString(), requester, approved.expiresAt());
    }

    private ResolvedAuthority resolveWorkforce(Jwt subject, AgentWorkloadIdentity requester, String audience,
                                               Set<String> scopes) {
        var actorClient = confidentialAuthority(requester.getOauthClientId(), requester.getTenantId());
        if (!actorClient.audience().equals(audience)) fail(INVALID_TARGET);
        String sourceClientId = required(subject, "client_id");
        var sourceClient = applications.activeAuthority(sourceClientId)
                .filter(value -> value.clientType() == TenantApplicationClient.Type.PUBLIC_BROWSER)
                .filter(value -> value.tenantId().equals(requester.getTenantId()))
                .orElseThrow(() -> new OAuth2AuthenticationException(INVALID_GRANT));
        if (!singleAudience(subject, sourceClient.audience())) fail(INVALID_GRANT);
        var workforce = applicationAccess.decisionAuthority(requester.getTenantId(),
                        actorClient.applicationId(), subject.getSubject())
                .orElseThrow(() -> new OAuth2AuthenticationException(INVALID_GRANT));
        Set<String> permitted = workforce.permissionEffects().keySet();
        requireScopeSubset(scopes, subjectScopes(subject), actorClient.scopes(), permitted);
        String authorityId = "workforce:" + actorClient.applicationId() + ":"
                + subject.getSubject() + ":" + workforce.entitlementRevision();
        return new ResolvedAuthority(Profile.WORKFORCE, TokenUse.EXCHANGE_SUBJECT, subject,
                requester.getTenantId(), audience, scopes, "workforce",
                "Workforce authority delegated to " + requester.getWorkloadRef(), authorityId,
                null, requester, subject.getExpiresAt());
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
        requireScopeSubset(scopes, subjectScopes(subject), route.getAllowedScopes(), broker.getAllowedScopes());
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
        if (Profile.WORKFORCE.name().toLowerCase().equals(profile)) {
            Actor initialActor = actor(subject);
            AgentWorkloadIdentity initial = requireActiveActor(initialActor, requester.getTenantId());
            if (!initial.getId().equals(requester.getId())) fail(INVALID_GRANT);
            requireWorkforceAuthority(subject, requester, scopes);
            AgentExchangeRoute outbound = activeRoute(requester.getTenantId(), requester.getId(), audience,
                    AgentExchangeRoute.DestinationType.GATEWAY, scopes);
            TrustedExchangeBroker broker = activeBrokerByAudience(requester.getTenantId(), audience);
            requireScopeSubset(scopes, subjectScopes(subject), outbound.getAllowedScopes(), broker.getAllowedScopes());
            return routeAuthority(Profile.WORKLOAD_CONTINUATION, TokenUse.GATEWAY_AUTHORIZATION,
                    subject, requester, outbound, required(subject, "identity_kind"), scopes);
        }
        if (!Profile.GATEWAY_BACKEND.name().toLowerCase().equals(profile)) fail(INVALID_GRANT);
        Actor previous = actor(subject);
        AgentExchangeRoute inbound = routeByAuthority(subject, requester.getTenantId());
        if (inbound.getDestinationType() != AgentExchangeRoute.DestinationType.AGENT
                || !requester.getId().equals(inbound.getDestinationWorkloadId())
                || !previous.workloadId().equals(inbound.getSourceWorkloadId())
                || !inbound.getAudience().equals(receivingAudience(requester))) fail(INVALID_GRANT);
        requireActiveActor(previous, requester.getTenantId());
        AgentExchangeRoute outbound = activeRoute(requester.getTenantId(), requester.getId(), audience,
                AgentExchangeRoute.DestinationType.GATEWAY, scopes);
        TrustedExchangeBroker broker = activeBrokerByAudience(requester.getTenantId(), audience);
        requireScopeSubset(scopes, subjectScopes(subject), outbound.getAllowedScopes(), broker.getAllowedScopes());
        return routeAuthority(Profile.WORKLOAD_CONTINUATION, TokenUse.GATEWAY_AUTHORIZATION,
                subject, requester, outbound, required(subject, "identity_kind"), scopes);
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
        Actor currentActor = actor(subject);
        AgentWorkloadIdentity source = requireActiveActor(currentActor, broker.getTenantId());
        if (!source.getOauthClientId().equals(required(subject, "client_id"))) fail(INVALID_GRANT);
        AgentExchangeRoute gatewayRoute = routeByAuthority(subject, broker.getTenantId());
        if (gatewayRoute.getDestinationType() != AgentExchangeRoute.DestinationType.GATEWAY
                || !source.getId().equals(gatewayRoute.getSourceWorkloadId())
                || !broker.getGatewayAudience().equals(gatewayRoute.getAudience())) fail(INVALID_GRANT);
        AgentExchangeRoute target = activeRoute(broker.getTenantId(), source.getId(), audience, null, scopes);
        if (target.getDestinationType() == AgentExchangeRoute.DestinationType.GATEWAY) fail(INVALID_TARGET);
        if (target.getDestinationType() == AgentExchangeRoute.DestinationType.AGENT) {
            AgentWorkloadIdentity destination = activeWorkload(broker.getTenantId(), target.getDestinationWorkloadId());
            if (!receivingAudience(destination).equals(audience)) fail(INVALID_TARGET);
            requireScopeSubset(scopes, confidentialAuthority(destination.getOauthClientId(), broker.getTenantId()).scopes());
        } else if (!applications.isActiveAudience(broker.getTenantId(), target.getAudience())) {
            fail(INVALID_TARGET);
        }
        requireScopeSubset(scopes, subjectScopes(subject), broker.getAllowedScopes(), target.getAllowedScopes());
        TokenUse use = target.getDestinationType() == AgentExchangeRoute.DestinationType.AGENT
                ? TokenUse.EXCHANGE_SUBJECT : TokenUse.DELEGATED_ACCESS;
        return routeAuthority(Profile.GATEWAY_BACKEND, use, subject, source, target,
                required(subject, "identity_kind"), scopes);
    }

    private ResolvedAuthority routeAuthority(Profile profile, TokenUse tokenUse, Jwt subject,
                                             AgentWorkloadIdentity actor, AgentExchangeRoute route,
                                             String identityKind, Set<String> scopes) {
        Instant expiry = route.getExpiresAt().isBefore(subject.getExpiresAt()) ? route.getExpiresAt() : subject.getExpiresAt();
        return new ResolvedAuthority(profile, tokenUse, subject, actor.getTenantId(), route.getAudience(),
                scopes, identityKind, route.getPurpose(), route.getId().toString(), null,
                actor, expiry);
    }

    private AgentExchangeRoute activeRoute(String tenantId, UUID sourceId, String audience,
                                           AgentExchangeRoute.DestinationType type, Set<String> requested) {
        AgentExchangeRoute match = null;
        for (AgentExchangeRoute route : routes.findByTenantIdAndSourceWorkloadIdAndAudienceAndStatus(
                tenantId, sourceId, audience, AgentExchangeRoute.Status.ACTIVE)) {
            if (!route.usableAt(clock.instant()) || (type != null && route.getDestinationType() != type)
                    || !route.getAllowedScopes().containsAll(requested)) continue;
            if (match != null) throw new OAuth2AuthenticationException(INVALID_GRANT);
            match = route;
        }
        if (match == null) throw new OAuth2AuthenticationException(INVALID_TARGET);
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

    private AgentWorkloadIdentity requireActiveActor(Actor actor, String tenantId) {
        AgentWorkloadIdentity workload = activeWorkload(tenantId, actor.workloadId());
        if (!workload.getWorkloadRef().equals(actor.workloadRef())
                || !workload.getOauthClientId().equals(actor.clientId())) fail(INVALID_GRANT);
        return workload;
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

    private AgentWorkloadIdentity activeWorkloadByClient(String clientId, String tenantId) {
        return workloads.findByOauthClientId(clientId)
                .filter(value -> value.getTenantId().equals(tenantId))
                .filter(value -> value.getStatus() == AgentWorkloadIdentity.Status.ACTIVE)
                .orElseThrow(() -> new OAuth2AuthenticationException(UNAUTHORIZED_CLIENT));
    }

    private AgentWorkloadIdentity activeWorkload(String tenantId, UUID id) {
        return workloads.findByTenantIdAndId(tenantId, id)
                .filter(value -> value.getStatus() == AgentWorkloadIdentity.Status.ACTIVE)
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
        return brokers.findByTenantIdAndOauthClientId(tenantId, clientId)
                .filter(value -> value.getStatus() == TrustedExchangeBroker.Status.ACTIVE)
                .orElseThrow(() -> new OAuth2AuthenticationException(INVALID_GRANT));
    }

    private TreeSet<String> approvedScopes(Collection<String> values) {
        TreeSet<String> scopes = new TreeSet<>();
        for (String value : values) {
            String scope = value.trim();
            if (scope.isBlank() || !businessScopes.isApproved(scope)) {
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
