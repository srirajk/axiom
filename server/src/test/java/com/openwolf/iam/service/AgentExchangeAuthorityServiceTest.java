package com.openwolf.iam.service;

import com.openwolf.iam.auth.BusinessScopeRegistry;
import com.openwolf.iam.dto.AgentExchangeContracts.CreateAgentExchangeRouteRequest;
import com.openwolf.iam.dto.AgentExchangeContracts.RegisterTrustedBrokerRequest;
import com.openwolf.iam.entity.AgentExchangeRoute;
import com.openwolf.iam.entity.AgentWorkloadIdentity;
import com.openwolf.iam.entity.TenantApplicationClient;
import com.openwolf.iam.entity.TrustedExchangeBroker;
import com.openwolf.iam.entity.TrustedExchangeBrokerTarget;
import com.openwolf.iam.exception.ResourceConflictException;
import com.openwolf.iam.repository.AgentExchangeRouteRepository;
import com.openwolf.iam.repository.AgentWorkloadIdentityRepository;
import com.openwolf.iam.repository.TrustedExchangeBrokerRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.jwt.Jwt;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class AgentExchangeAuthorityServiceTest {
    private static final String TENANT = "meridian";
    private static final String SCOPE = "cards:incident.read";
    private static final String SOURCE_CLIENT = "card-assistance-agent";
    private static final String DESTINATION_CLIENT = "card-actions-agent";
    private static final String GATEWAY_CLIENT = "argus-gateway-broker";
    private static final String BROKER_SCOPE = "gateway:exchange";
    private static final String SOURCE_AUDIENCE = "cards-api";
    private static final String DESTINATION_AUDIENCE = "card-actions-api";
    private static final String GATEWAY_AUDIENCE = "argus-gateway";
    private static final Instant NOW = Instant.parse("2026-09-21T12:00:00Z");

    private final TrustedExchangeBrokerRepository brokers = mock(TrustedExchangeBrokerRepository.class);
    private final AgentExchangeRouteRepository routes = mock(AgentExchangeRouteRepository.class);
    private final AgentWorkloadIdentityRepository workloads = mock(AgentWorkloadIdentityRepository.class);
    private final TenantApplicationService applications = mock(TenantApplicationService.class);
    private final ApplicationAccessService applicationAccess = mock(ApplicationAccessService.class);
    private final CiamDelegationAuthorityService customerAuthority = mock(CiamDelegationAuthorityService.class);
    private final CiamLifecycleAuditService audit = mock(CiamLifecycleAuditService.class);
    private final TrustedBrokerTargetService targetService = mock(TrustedBrokerTargetService.class);
    private AgentExchangeAuthorityService service;
    private AgentWorkloadIdentity source;
    private AgentWorkloadIdentity destination;
    private TrustedExchangeBroker broker;
    private AgentExchangeRoute gatewayRoute;
    private AgentExchangeRoute agentRoute;
    private UUID sourceApplicationId;

    @BeforeEach
    void setUp() {
        service = new AgentExchangeAuthorityService(brokers, routes, workloads, applications,
                applicationAccess, customerAuthority, audit, new BusinessScopeRegistry(SCOPE),
                Clock.fixed(NOW, ZoneOffset.UTC));
        service.setBrokerTargets(targetService);
        source = new AgentWorkloadIdentity(TENANT, "agent:card-assistance:development",
                "Card Assistance Agent", SOURCE_CLIENT, NOW);
        destination = new AgentWorkloadIdentity(TENANT, "agent:card-actions:development",
                "Card Actions Agent", DESTINATION_CLIENT, NOW);
        broker = new TrustedExchangeBroker(TENANT, GATEWAY_CLIENT, GATEWAY_AUDIENCE,
                List.of(BROKER_SCOPE), NOW);
        gatewayRoute = new AgentExchangeRoute(TENANT, source.getId(),
                AgentExchangeRoute.DestinationType.GATEWAY, null, GATEWAY_AUDIENCE,
                List.of(SCOPE), "Route bounded work through Argus Gateway", NOW.plusSeconds(3600), NOW);
        agentRoute = new AgentExchangeRoute(TENANT, source.getId(),
                AgentExchangeRoute.DestinationType.AGENT, destination.getId(), DESTINATION_AUDIENCE,
                List.of(SCOPE), "Delegate bounded card action work", NOW.plusSeconds(3600), NOW);
        sourceApplicationId = UUID.randomUUID();
        UUID destinationApplicationId = UUID.randomUUID();
        UUID gatewayApplicationId = UUID.randomUUID();

        when(workloads.findByOauthClientId(SOURCE_CLIENT)).thenReturn(Optional.of(source));
        when(workloads.findByOauthClientId(DESTINATION_CLIENT)).thenReturn(Optional.of(destination));
        when(workloads.findByTenantIdAndId(TENANT, source.getId())).thenReturn(Optional.of(source));
        when(workloads.findByTenantIdAndId(TENANT, destination.getId())).thenReturn(Optional.of(destination));
        when(applications.activeAuthority(SOURCE_CLIENT)).thenReturn(Optional.of(authority(
                SOURCE_AUDIENCE, TenantApplicationClient.Type.CONFIDENTIAL_SERVICE, sourceApplicationId)));
        when(applications.activeAuthority(DESTINATION_CLIENT)).thenReturn(Optional.of(authority(
                DESTINATION_AUDIENCE, TenantApplicationClient.Type.CONFIDENTIAL_SERVICE,
                destinationApplicationId)));
        when(applications.activeAuthority(GATEWAY_CLIENT)).thenReturn(Optional.of(authority(
                GATEWAY_AUDIENCE, TenantApplicationClient.Type.CONFIDENTIAL_SERVICE,
                gatewayApplicationId)));
        when(applications.activeAuthority("card-customer-web")).thenReturn(Optional.of(authority(
                SOURCE_AUDIENCE, TenantApplicationClient.Type.PUBLIC_BROWSER, sourceApplicationId)));
        when(brokers.findByOauthClientId(GATEWAY_CLIENT)).thenReturn(Optional.of(broker));
        when(brokers.findByTenantIdAndOauthClientId(TENANT, GATEWAY_CLIENT)).thenReturn(Optional.of(broker));
        when(brokers.findByTenantIdAndGatewayAudience(TENANT, GATEWAY_AUDIENCE)).thenReturn(Optional.of(broker));
        when(routes.findByTenantIdAndId(TENANT, gatewayRoute.getId())).thenReturn(Optional.of(gatewayRoute));
        when(routes.findByTenantIdAndId(TENANT, agentRoute.getId())).thenReturn(Optional.of(agentRoute));
        when(routes.findByTenantIdAndSourceWorkloadIdAndAudienceAndStatus(
                TENANT, source.getId(), GATEWAY_AUDIENCE, AgentExchangeRoute.Status.ACTIVE))
                .thenReturn(List.of(gatewayRoute));
        when(routes.findByTenantIdAndSourceWorkloadIdAndAudienceAndStatus(
                TENANT, source.getId(), DESTINATION_AUDIENCE, AgentExchangeRoute.Status.ACTIVE))
                .thenReturn(List.of(agentRoute));
        when(routes.save(any(AgentExchangeRoute.class))).thenAnswer(invocation -> invocation.getArgument(0));
        when(targetService.resolve(eq(TENANT), eq(broker.getId()), any())).thenReturn(Optional.empty());
    }

    @Test
    void workforceAuthorityCreatesOneExactAgentExchangeSubject() {
        when(applicationAccess.decisionAuthority(TENANT, sourceApplicationId, "meridian-1008"))
                .thenReturn(Optional.of(new ApplicationAccessService.DecisionAuthority(
                        "card-assistance", 7, Set.of("card-incident-operator"),
                        Map.of(SCOPE, "allow"), Map.of(), "policy-v1")));
        Jwt workforce = token("meridian-1008", SOURCE_AUDIENCE, Map.of(
                "tenant_id", TENANT,
                "identity_kind", "workforce",
                "client_id", "card-customer-web",
                "scope", SCOPE));

        var resolved = service.resolve(workforce, SOURCE_CLIENT, SOURCE_AUDIENCE, Set.of(SCOPE));

        assertThat(resolved.profile()).isEqualTo(AgentExchangeAuthorityService.Profile.WORKFORCE);
        assertThat(resolved.tokenUse()).isEqualTo(AgentExchangeAuthorityService.TokenUse.EXCHANGE_SUBJECT);
        assertThat(resolved.subject().getSubject()).isEqualTo("meridian-1008");
        assertThat(resolved.actingWorkload().getId()).isEqualTo(source.getId());
        assertThat(resolved.scopes()).containsExactly(SCOPE);
        assertThat(resolved.authorityId()).startsWith("workforce:" + sourceApplicationId + ":meridian-1008:7");
    }

    @Test
    void workforceTokenFromAnotherApplicationCannotBorrowActorApplicationAuthority() {
        UUID otherApplicationId = UUID.randomUUID();
        when(applications.activeAuthority("card-customer-web")).thenReturn(Optional.of(authority(
                SOURCE_AUDIENCE, TenantApplicationClient.Type.PUBLIC_BROWSER, otherApplicationId)));
        when(applicationAccess.decisionAuthority(TENANT, sourceApplicationId, "meridian-1008"))
                .thenReturn(Optional.of(new ApplicationAccessService.DecisionAuthority(
                        "card-assistance", 7, Set.of("card-incident-operator"),
                        Map.of(SCOPE, "allow"), Map.of(), "policy-v1")));
        Jwt workforce = token("meridian-1008", SOURCE_AUDIENCE, Map.of(
                "tenant_id", TENANT,
                "identity_kind", "workforce",
                "client_id", "card-customer-web",
                "scope", SCOPE));

        assertThatThrownBy(() -> service.resolve(workforce, SOURCE_CLIENT, SOURCE_AUDIENCE, Set.of(SCOPE)))
                .isInstanceOf(OAuth2AuthenticationException.class)
                .satisfies(error -> assertThat(((OAuth2AuthenticationException) error).getError().getErrorCode())
                        .isEqualTo("invalid_grant"));
        org.mockito.Mockito.verify(applicationAccess, org.mockito.Mockito.never())
                .decisionAuthority(TENANT, sourceApplicationId, "meridian-1008");
    }

    @Test
    void autonomousWorkloadCanReachOnlyItsApprovedGatewayRoute() {
        Jwt workload = token(SOURCE_CLIENT, SOURCE_AUDIENCE, Map.of(
                "tenant_id", TENANT,
                "identity_kind", "workload",
                "client_id", SOURCE_CLIENT,
                "scope", SCOPE));

        var resolved = service.resolve(workload, SOURCE_CLIENT, GATEWAY_AUDIENCE, Set.of(SCOPE));

        assertThat(resolved.profile()).isEqualTo(AgentExchangeAuthorityService.Profile.WORKLOAD_CONTINUATION);
        assertThat(resolved.tokenUse()).isEqualTo(AgentExchangeAuthorityService.TokenUse.GATEWAY_AUTHORIZATION);
        assertThat(resolved.authorityId()).isEqualTo(gatewayRoute.getId().toString());
        assertThatThrownBy(() -> service.resolve(workload, SOURCE_CLIENT, "unapproved-api", Set.of(SCOPE)))
                .isInstanceOf(OAuth2AuthenticationException.class);
    }

    @Test
    void workloadRegisteredFirstCannotBecomeBroker() {
        assertThatThrownBy(() -> service.registerBroker(TENANT,
                new RegisterTrustedBrokerRequest(SOURCE_CLIENT, GATEWAY_AUDIENCE, Set.of(SCOPE)),
                "admin", "test"))
                .isInstanceOf(ResourceConflictException.class)
                .hasMessageContaining("broker cannot be an Agent workload");
        var order = org.mockito.Mockito.inOrder(applications, workloads);
        order.verify(applications).lockClientForIdentityRegistration(SOURCE_CLIENT);
        order.verify(workloads).findByOauthClientId(SOURCE_CLIENT);
        org.mockito.Mockito.verify(brokers, org.mockito.Mockito.never()).save(any(TrustedExchangeBroker.class));
    }

    @Test
    void originalWorkloadSubjectRequiresActiveBindingAndExactRegisteredAudience() {
        Jwt workload = token(SOURCE_CLIENT, SOURCE_AUDIENCE, Map.of(
                "tenant_id", TENANT,
                "identity_kind", "workload",
                "client_id", SOURCE_CLIENT,
                "scope", SCOPE));
        service.requireValidNonCustomerSubject(workload);

        Jwt wrongAudience = token(SOURCE_CLIENT, "other-agent-api", Map.of(
                "tenant_id", TENANT,
                "identity_kind", "workload",
                "client_id", SOURCE_CLIENT,
                "scope", SCOPE));
        assertThatThrownBy(() -> service.requireValidNonCustomerSubject(wrongAudience))
                .isInstanceOf(OAuth2AuthenticationException.class);

        source.revoke(NOW);
        assertThatThrownBy(() -> service.requireValidNonCustomerSubject(workload))
                .isInstanceOf(OAuth2AuthenticationException.class);
    }

    @Test
    void trustedGatewayMintsOnlyTheApprovedDestinationAgentSubject() {
        Jwt gatewaySubject = gatewayAuthorization(TENANT);

        var resolved = service.resolve(gatewaySubject, GATEWAY_CLIENT,
                DESTINATION_AUDIENCE, Set.of(SCOPE));

        assertThat(resolved.profile()).isEqualTo(AgentExchangeAuthorityService.Profile.GATEWAY_BACKEND);
        assertThat(resolved.tokenUse()).isEqualTo(AgentExchangeAuthorityService.TokenUse.EXCHANGE_SUBJECT);
        assertThat(resolved.audience()).isEqualTo(DESTINATION_AUDIENCE);
        assertThat(resolved.actingWorkload().getId()).isEqualTo(source.getId());
        assertThatThrownBy(() -> service.resolve(gatewaySubject, GATEWAY_CLIENT,
                "sibling-agent-api", Set.of(SCOPE)))
                .isInstanceOf(OAuth2AuthenticationException.class);
    }

    @Test
    void brokerOwnedTargetReplacesPerSourceTargetRouteButNotGatewayEntryRoute() {
        TrustedExchangeBrokerTarget target = new TrustedExchangeBrokerTarget(broker.getId(), TENANT,
                DESTINATION_AUDIENCE, AgentExchangeRoute.DestinationType.AGENT, destination.getId(),
                List.of(SCOPE), "Broker target", NOW);
        when(targetService.resolve(TENANT, broker.getId(), DESTINATION_AUDIENCE)).thenReturn(Optional.of(target));
        Jwt gatewaySubject = gatewayAuthorization(TENANT);

        var result = service.resolve(gatewaySubject, GATEWAY_CLIENT, DESTINATION_AUDIENCE, Set.of(SCOPE));

        assertThat(result.authorityId()).isEqualTo("broker-target:" + target.getId());
        assertThat(result.tokenUse()).isEqualTo(AgentExchangeAuthorityService.TokenUse.EXCHANGE_SUBJECT);
        org.mockito.Mockito.verify(routes, org.mockito.Mockito.never())
                .findByTenantIdAndSourceWorkloadIdAndAudienceAndStatus(TENANT, source.getId(),
                        DESTINATION_AUDIENCE, AgentExchangeRoute.Status.ACTIVE);
        verify(routes).findByTenantIdAndId(TENANT, gatewayRoute.getId());
    }

    @Test
    void brokerTargetScopesAreBoundBySubjectAndDestinationNotBrokerScopes() {
        TrustedExchangeBrokerTarget target = new TrustedExchangeBrokerTarget(broker.getId(), TENANT,
                DESTINATION_AUDIENCE, AgentExchangeRoute.DestinationType.AGENT, destination.getId(),
                List.of(SCOPE), "Broker target", NOW);
        when(targetService.resolve(TENANT, broker.getId(), DESTINATION_AUDIENCE)).thenReturn(Optional.of(target));

        var resolved = service.resolve(gatewayAuthorization(TENANT), GATEWAY_CLIENT,
                DESTINATION_AUDIENCE, Set.of(SCOPE));
        assertThat(resolved.scopes()).containsExactly(SCOPE);
        assertThat(broker.getAllowedScopes()).containsExactly(BROKER_SCOPE);

        TrustedExchangeBrokerTarget narrower = new TrustedExchangeBrokerTarget(broker.getId(), TENANT,
                DESTINATION_AUDIENCE, AgentExchangeRoute.DestinationType.AGENT, destination.getId(),
                List.of("other:scope"), "Narrower target", NOW);
        when(targetService.resolve(TENANT, broker.getId(), DESTINATION_AUDIENCE)).thenReturn(Optional.of(narrower));
        assertThatThrownBy(() -> service.resolve(gatewayAuthorization(TENANT), GATEWAY_CLIENT,
                DESTINATION_AUDIENCE, Set.of(SCOPE)))
                .isInstanceOf(OAuth2AuthenticationException.class)
                .satisfies(error -> assertThat(((OAuth2AuthenticationException) error).getError().getErrorCode())
                        .isEqualTo("invalid_scope"));

        Jwt subjectWithoutRequestedScope = token("meridian-1008", GATEWAY_AUDIENCE, Map.of(
                "tenant_id", TENANT, "identity_kind", "workforce", "client_id", SOURCE_CLIENT,
                "scope", "", "token_use", "gateway_authorization", "authority_profile", "workload_continuation",
                "authority_id", gatewayRoute.getId().toString(), "act", actor(source)));
        when(targetService.resolve(TENANT, broker.getId(), DESTINATION_AUDIENCE)).thenReturn(Optional.of(target));
        assertThatThrownBy(() -> service.resolve(subjectWithoutRequestedScope, GATEWAY_CLIENT,
                DESTINATION_AUDIENCE, Set.of(SCOPE)))
                .isInstanceOf(OAuth2AuthenticationException.class)
                .satisfies(error -> assertThat(((OAuth2AuthenticationException) error).getError().getErrorCode())
                        .isEqualTo("invalid_scope"));
    }

    @Test
    void gatewayRouteMayCarryBusinessScopesBeyondBrokerInvocationScopes() {
        var request = new CreateAgentExchangeRouteRequest(source.getId(),
                AgentExchangeRoute.DestinationType.GATEWAY, null, GATEWAY_AUDIENCE, Set.of(SCOPE),
                "Route business scope through trusted Gateway", NOW.plusSeconds(3600));

        var created = service.createRoute(TENANT, request, "admin", "route-create");

        assertThat(created.scopes()).containsExactly(SCOPE);
        assertThat(broker.getAllowedScopes()).containsExactly(BROKER_SCOPE);
    }

    @Test
    void brokerTargetRequiresAnActiveGatewayEntryAndDoesNotRequireAPerSourceTargetRoute() {
        TrustedExchangeBrokerTarget target = new TrustedExchangeBrokerTarget(broker.getId(), TENANT,
                DESTINATION_AUDIENCE, AgentExchangeRoute.DestinationType.AGENT, destination.getId(),
                List.of(SCOPE), "Broker target", NOW);
        when(targetService.resolve(TENANT, broker.getId(), DESTINATION_AUDIENCE)).thenReturn(Optional.of(target));

        var result = service.resolve(gatewayAuthorization(TENANT), GATEWAY_CLIENT,
                DESTINATION_AUDIENCE, Set.of(SCOPE));
        assertThat(result.authorityId()).isEqualTo("broker-target:" + target.getId());
        org.mockito.Mockito.verify(routes, org.mockito.Mockito.never())
                .findByTenantIdAndSourceWorkloadIdAndAudienceAndStatus(TENANT, source.getId(),
                        DESTINATION_AUDIENCE, AgentExchangeRoute.Status.ACTIVE);

        gatewayRoute.revoke(NOW.plusSeconds(1));
        assertThatThrownBy(() -> service.resolve(gatewayAuthorization(TENANT), GATEWAY_CLIENT,
                DESTINATION_AUDIENCE, Set.of(SCOPE)))
                .isInstanceOf(OAuth2AuthenticationException.class)
                .satisfies(error -> assertThat(((OAuth2AuthenticationException) error).getError().getErrorCode())
                        .isEqualTo("invalid_grant"));
    }

    @Test
    void brokerTargetTokenExpiryCannotOutliveTheGatewayEntryRoute() {
        TrustedExchangeBrokerTarget target = new TrustedExchangeBrokerTarget(broker.getId(), TENANT,
                DESTINATION_AUDIENCE, AgentExchangeRoute.DestinationType.AGENT, destination.getId(),
                List.of(SCOPE), "Broker target", NOW);
        when(targetService.resolve(TENANT, broker.getId(), DESTINATION_AUDIENCE)).thenReturn(Optional.of(target));
        Jwt original = Jwt.withTokenValue("long-lived-source").header("alg", "RS256")
                .subject(SOURCE_CLIENT).issuedAt(NOW.minusSeconds(30)).expiresAt(NOW.plusSeconds(7200))
                .audience(List.of(SOURCE_AUDIENCE)).claim("tenant_id", TENANT)
                .claim("identity_kind", "workload").claim("client_id", SOURCE_CLIENT)
                .claim("scope", SCOPE).build();

        var gateway = service.resolve(original, SOURCE_CLIENT, GATEWAY_AUDIENCE, Set.of(SCOPE));
        assertThat(gateway.authorityExpiresAt()).isEqualTo(gatewayRoute.getExpiresAt());
        Jwt gatewayToken = Jwt.withTokenValue("route-bounded-gateway-token").header("alg", "RS256")
                .subject(SOURCE_CLIENT).issuedAt(NOW.minusSeconds(30)).expiresAt(gateway.authorityExpiresAt())
                .audience(List.of(GATEWAY_AUDIENCE)).claim("tenant_id", TENANT)
                .claim("identity_kind", "workload").claim("client_id", SOURCE_CLIENT)
                .claim("scope", SCOPE).claim("token_use", "gateway_authorization")
                .claim("authority_profile", "workload_continuation")
                .claim("authority_id", gatewayRoute.getId().toString()).build();

        var backend = service.resolve(gatewayToken, GATEWAY_CLIENT, DESTINATION_AUDIENCE, Set.of(SCOPE));
        assertThat(backend.authorityExpiresAt()).isEqualTo(gatewayRoute.getExpiresAt());
    }

    @Test
    void brokerTargetPreservesThePersonActorChainAndSelfActingSourceHasNoActor() {
        TrustedExchangeBrokerTarget target = new TrustedExchangeBrokerTarget(broker.getId(), TENANT,
                DESTINATION_AUDIENCE, AgentExchangeRoute.DestinationType.AGENT, destination.getId(),
                List.of(SCOPE), "Broker target", NOW);
        when(targetService.resolve(TENANT, broker.getId(), DESTINATION_AUDIENCE)).thenReturn(Optional.of(target));
        Map<String, Object> prior = Map.of("sub", "agent:prior", "client_id", "prior-client",
                "workload_id", UUID.randomUUID().toString());
        Map<String, Object> chain = Map.of("sub", source.getWorkloadRef(), "client_id", SOURCE_CLIENT,
                "workload_id", source.getId().toString(), "act", prior);
        Jwt person = gatewayAuthorizationWithActor(chain);

        var personResult = service.resolve(person, GATEWAY_CLIENT, DESTINATION_AUDIENCE, Set.of(SCOPE));
        assertThat((Object) personResult.subject().getClaim("act")).isEqualTo(chain);
        assertThat(personResult.actingWorkload().getId()).isEqualTo(source.getId());
        assertThat(personResult.authorityId()).isEqualTo("broker-target:" + target.getId());

        Jwt self = token(SOURCE_CLIENT, GATEWAY_AUDIENCE, Map.of(
                "tenant_id", TENANT, "identity_kind", "workload", "client_id", SOURCE_CLIENT,
                "scope", SCOPE, "token_use", "gateway_authorization",
                "authority_profile", "workload_continuation", "authority_id", gatewayRoute.getId().toString()));
        var selfResult = service.resolve(self, GATEWAY_CLIENT, DESTINATION_AUDIENCE, Set.of(SCOPE));
        assertThat(selfResult.subject().getClaims()).doesNotContainKey("act");
        assertThat(selfResult.actingWorkload().getOauthClientId()).isEqualTo(SOURCE_CLIENT);
    }

    @Test
    void anotherBrokerCannotBorrowAnExistingBrokersTarget() {
        TrustedExchangeBroker other = new TrustedExchangeBroker(TENANT, "other-broker", "other-gateway",
                List.of(SCOPE), NOW);
        when(brokers.findByOauthClientId("other-broker")).thenReturn(Optional.of(other));
        TrustedExchangeBrokerTarget target = new TrustedExchangeBrokerTarget(broker.getId(), TENANT,
                DESTINATION_AUDIENCE, AgentExchangeRoute.DestinationType.AGENT, destination.getId(),
                List.of(SCOPE), "Broker target", NOW);
        when(targetService.resolve(TENANT, broker.getId(), DESTINATION_AUDIENCE)).thenReturn(Optional.of(target));

        assertThatThrownBy(() -> service.resolve(gatewayAuthorization(TENANT), "other-broker",
                DESTINATION_AUDIENCE, Set.of(SCOPE)))
                .isInstanceOf(OAuth2AuthenticationException.class)
                .satisfies(error -> assertThat(((OAuth2AuthenticationException) error).getError().getErrorCode())
                        .isEqualTo("invalid_grant"));
        org.mockito.Mockito.verify(targetService, org.mockito.Mockito.never())
                .resolve(TENANT, other.getId(), DESTINATION_AUDIENCE);
    }

    @Test
    void brokerOwnedTargetRevocationInvalidatesAlreadyIssuedToken() {
        TrustedExchangeBrokerTarget target = new TrustedExchangeBrokerTarget(broker.getId(), TENANT,
                DESTINATION_AUDIENCE, AgentExchangeRoute.DestinationType.AGENT, destination.getId(),
                List.of(SCOPE), "Broker target", NOW);
        when(targetService.requireActive(TENANT, broker.getId(), target.getId())).thenReturn(target);
        Jwt issued = token("meridian-1008", DESTINATION_AUDIENCE, Map.of(
                "tenant_id", TENANT, "identity_kind", "workforce", "client_id", GATEWAY_CLIENT,
                "scope", SCOPE, "token_use", "exchange_subject", "authority_profile", "gateway_backend",
                "authority_id", "broker-target:" + target.getId(), "act", actor(source),
                "source_gateway_route_id", gatewayRoute.getId().toString()));

        service.requireValidNonCustomerSubject(issued);
        target.revoke(NOW.plusSeconds(1));
        when(targetService.requireActive(TENANT, broker.getId(), target.getId()))
                .thenThrow(new OAuth2AuthenticationException(new org.springframework.security.oauth2.core.OAuth2Error("invalid_grant")));
        assertThatThrownBy(() -> service.requireValidNonCustomerSubject(issued))
                .isInstanceOf(OAuth2AuthenticationException.class);
    }

    @Test
    void gatewayEntryRevocationInvalidatesAlreadyIssuedBrokerTargetToken() {
        TrustedExchangeBrokerTarget target = new TrustedExchangeBrokerTarget(broker.getId(), TENANT,
                DESTINATION_AUDIENCE, AgentExchangeRoute.DestinationType.AGENT, destination.getId(),
                List.of(SCOPE), "Broker target", NOW);
        when(targetService.requireActive(TENANT, broker.getId(), target.getId())).thenReturn(target);
        Jwt issued = token("meridian-1008", DESTINATION_AUDIENCE, Map.of(
                "tenant_id", TENANT, "identity_kind", "workforce", "client_id", GATEWAY_CLIENT,
                "scope", SCOPE, "token_use", "exchange_subject", "authority_profile", "gateway_backend",
                "authority_id", "broker-target:" + target.getId(), "act", actor(source),
                "source_gateway_route_id", gatewayRoute.getId().toString()));

        service.requireValidNonCustomerSubject(issued);
        gatewayRoute.revoke(NOW.plusSeconds(1));
        assertThatThrownBy(() -> service.requireValidNonCustomerSubject(issued))
                .isInstanceOf(OAuth2AuthenticationException.class)
                .satisfies(error -> assertThat(((OAuth2AuthenticationException) error).getError().getErrorCode())
                        .isEqualTo("invalid_grant"));
    }

    @Test
    void revokedBrokerTargetCannotFallBackToExistingSourceRoute() {
        when(targetService.resolve(TENANT, broker.getId(), DESTINATION_AUDIENCE))
                .thenThrow(new OAuth2AuthenticationException(new org.springframework.security.oauth2.core.OAuth2Error("invalid_target")));

        assertThatThrownBy(() -> service.resolve(gatewayAuthorization(TENANT), GATEWAY_CLIENT,
                DESTINATION_AUDIENCE, Set.of(SCOPE)))
                .isInstanceOf(OAuth2AuthenticationException.class)
                .satisfies(error -> assertThat(((OAuth2AuthenticationException) error).getError().getErrorCode())
                        .isEqualTo("invalid_target"));
        org.mockito.Mockito.verify(routes, org.mockito.Mockito.never())
                .findByTenantIdAndSourceWorkloadIdAndAudienceAndStatus(TENANT, source.getId(),
                        DESTINATION_AUDIENCE, AgentExchangeRoute.Status.ACTIVE);
    }

    @Test
    void selfActingWorkloadResourceTokenKeepsSourceBindingWithoutAct() {
        TrustedExchangeBrokerTarget target = new TrustedExchangeBrokerTarget(broker.getId(), TENANT,
                "orders-api", AgentExchangeRoute.DestinationType.RESOURCE, null,
                List.of(SCOPE), "Broker resource target", NOW);
        when(targetService.requireActive(TENANT, broker.getId(), target.getId())).thenReturn(target);
        when(applications.isActiveAudience(TENANT, "orders-api")).thenReturn(true);
        Jwt issued = token(SOURCE_CLIENT, "orders-api", Map.of(
                "tenant_id", TENANT, "identity_kind", "workload", "client_id", GATEWAY_CLIENT,
                "scope", SCOPE, "token_use", "delegated_access", "authority_profile", "gateway_backend",
                "authority_id", "broker-target:" + target.getId(),
                "source_workload_id", source.getId().toString(),
                "source_gateway_route_id", gatewayRoute.getId().toString()));

        service.requireValidIssuedToken(issued);
        org.mockito.Mockito.verify(workloads).findByOauthClientId(SOURCE_CLIENT);
        assertThatThrownBy(() -> service.requireValidIssuedToken(token("unregistered-client", "orders-api", Map.of(
                "tenant_id", TENANT, "identity_kind", "workload", "client_id", GATEWAY_CLIENT,
                "scope", SCOPE, "token_use", "delegated_access", "authority_profile", "gateway_backend",
                "authority_id", "broker-target:" + target.getId(),
                "source_workload_id", source.getId().toString(),
                "source_gateway_route_id", gatewayRoute.getId().toString()))))
                .isInstanceOf(OAuth2AuthenticationException.class);
        assertThatThrownBy(() -> service.requireValidIssuedToken(token(SOURCE_CLIENT, "orders-api", Map.of(
                "tenant_id", TENANT, "identity_kind", "workload", "client_id", GATEWAY_CLIENT,
                "scope", SCOPE, "token_use", "delegated_access", "authority_profile", "gateway_backend",
                "authority_id", "broker-target:" + target.getId(),
                "source_workload_id", UUID.randomUUID().toString(),
                "source_gateway_route_id", gatewayRoute.getId().toString()))))
                .as("a new registration using the old client ID cannot inherit the old token")
                .isInstanceOf(OAuth2AuthenticationException.class);
        source.revoke(NOW.plusSeconds(1));
        assertThatThrownBy(() -> service.requireValidIssuedToken(issued))
                .isInstanceOf(OAuth2AuthenticationException.class);
    }

    @Test
    void crossTenantAndMalformedActorClaimsFailClosed() {
        Jwt crossTenant = gatewayAuthorization("other-tenant");
        assertThatThrownBy(() -> service.resolve(crossTenant, GATEWAY_CLIENT,
                DESTINATION_AUDIENCE, Set.of(SCOPE)))
                .isInstanceOf(OAuth2AuthenticationException.class);

        Jwt malformed = token("meridian-1008", GATEWAY_AUDIENCE, Map.of(
                "tenant_id", TENANT,
                "identity_kind", "workforce",
                "client_id", SOURCE_CLIENT,
                "scope", SCOPE,
                "token_use", "gateway_authorization",
                "authority_profile", "workload_continuation",
                "authority_id", gatewayRoute.getId().toString(),
                "act", Map.of("client_id", SOURCE_CLIENT, "workload_id", source.getId().toString())));
        assertThatThrownBy(() -> service.requireValidNonCustomerSubject(malformed))
                .isInstanceOf(OAuth2AuthenticationException.class);
    }

    @Test
    void actorIdentityRequiresExactWorkloadIdReferenceAndClient() {
        service.requireValidNonCustomerSubject(gatewayAuthorization(TENANT));

        assertThatThrownBy(() -> service.requireValidNonCustomerSubject(
                gatewayAuthorizationWithActor(Map.of(
                        "sub", source.getWorkloadRef(), "client_id", SOURCE_CLIENT,
                        "workload_id", UUID.randomUUID().toString()))))
                .isInstanceOf(OAuth2AuthenticationException.class);
        assertThatThrownBy(() -> service.requireValidNonCustomerSubject(
                gatewayAuthorizationWithActor(Map.of(
                        "sub", "agent:other:development", "client_id", SOURCE_CLIENT,
                        "workload_id", source.getId().toString()))))
                .isInstanceOf(OAuth2AuthenticationException.class);
        assertThatThrownBy(() -> service.requireValidNonCustomerSubject(
                gatewayAuthorizationWithActor(Map.of(
                        "sub", source.getWorkloadRef(), "client_id", DESTINATION_CLIENT,
                        "workload_id", source.getId().toString()))))
                .isInstanceOf(OAuth2AuthenticationException.class);
    }

    @Test
    void routeRevocationInvalidatesAnAlreadyIssuedAgentSubject() {
        Jwt agentSubject = token("meridian-1008", DESTINATION_AUDIENCE, Map.of(
                "tenant_id", TENANT,
                "identity_kind", "workforce",
                "client_id", GATEWAY_CLIENT,
                "scope", SCOPE,
                "token_use", "exchange_subject",
                "authority_profile", "gateway_backend",
                "authority_id", agentRoute.getId().toString(),
                "act", actor(source)));
        service.requireValidNonCustomerSubject(agentSubject);

        agentRoute.revoke(NOW.plusSeconds(1));

        assertThatThrownBy(() -> service.requireValidNonCustomerSubject(agentSubject))
                .isInstanceOf(OAuth2AuthenticationException.class);
    }

    @Test
    void resourceRouteMustNameAnActiveTenantApplicationAudience() {
        when(applications.isActiveAudience(TENANT, "card-case-api")).thenReturn(false);
        var request = new CreateAgentExchangeRouteRequest(source.getId(),
                AgentExchangeRoute.DestinationType.RESOURCE, null, "card-case-api", Set.of(SCOPE),
                "Read the governed card incident case", NOW.plusSeconds(3600));

        assertThatThrownBy(() -> service.createRoute(TENANT, request, "admin", "test"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("active tenant application audience");
    }

    @Test
    void routeLifecycleAuditUsesWorkloadIdsRatherThanAgentNames() {
        var request = new CreateAgentExchangeRouteRequest(source.getId(),
                AgentExchangeRoute.DestinationType.AGENT, destination.getId(), DESTINATION_AUDIENCE,
                Set.of(SCOPE), "Delegate bounded card action work", NOW.plusSeconds(3600));
        service.createRoute(TENANT, request, "admin", "test-create");
        verify(audit).record(eq(TENANT), eq("admin"), eq("AGENT_EXCHANGE_ROUTE_CREATED"),
                eq("agent_exchange_route"), any(), argThat(details ->
                        source.getId().equals(details.get("sourceWorkloadId"))
                        && destination.getId().equals(details.get("destinationWorkloadId"))
                        && AgentExchangeRoute.DestinationType.AGENT.equals(details.get("destinationType"))),
                eq("test-create"));

        service.revokeRoute(TENANT, agentRoute.getId(), "admin", "test-revoke");
        verify(audit).record(eq(TENANT), eq("admin"), eq("AGENT_EXCHANGE_ROUTE_REVOKED"),
                eq("agent_exchange_route"), eq(agentRoute.getId().toString()), argThat(details ->
                        source.getId().equals(details.get("sourceWorkloadId"))
                        && destination.getId().equals(details.get("destinationWorkloadId"))
                        && AgentExchangeRoute.DestinationType.AGENT.equals(details.get("destinationType"))),
                eq("test-revoke"));
    }

    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    void duplicateMatchingResourceRoutesFailClosedOnFirstHop(boolean customer) {
        Jwt person = personResourceSubject(customer);
        var first = resourceRoute(NOW.plusSeconds(60));
        var second = resourceRoute(NOW.plusSeconds(120));
        resourceRoutes(first, second);
        assertThatThrownBy(() -> service.resolve(person, SOURCE_CLIENT, DESTINATION_AUDIENCE, Set.of(SCOPE)))
                .isInstanceOf(AgentExchangeAuthorityService.RouteDenied.class)
                .satisfies(error -> {
                    var denied = (AgentExchangeAuthorityService.RouteDenied) error;
                    assertThat(denied.getError().getErrorCode()).isEqualTo("invalid_grant");
                    assertThat(denied.routeId()).isNull();
                    assertThat(denied.destinationType()).isEqualTo(AgentExchangeRoute.DestinationType.RESOURCE);
                });
    }

    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    void resourceExpiryIsTheMinimumOfRouteAndSubject(boolean customer) {
        Jwt person = personResourceSubject(customer);
        for (long seconds : List.of(60L, 3600L)) {
            var route = resourceRoute(NOW.plusSeconds(seconds));
            resourceRoutes(route);
            var result = service.resolve(person, SOURCE_CLIENT, DESTINATION_AUDIENCE, Set.of(SCOPE));
            assertThat(result.authorityExpiresAt()).isEqualTo(seconds < 600 ? route.getExpiresAt() : person.getExpiresAt());
            assertThat(result.routeId()).isEqualTo(route.getId().toString());
            assertThat(result.destinationType()).isEqualTo(AgentExchangeRoute.DestinationType.RESOURCE);
        }
    }

    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    void resourceRouteCannotBypassSubjectClientApplicationTenantAudienceOrActivityChecks(boolean customer) {
        Jwt person = personResourceSubject(customer);
        resourceRoutes(resourceRoute(NOW.plusSeconds(600)));
        var client = applications.activeAuthority("card-customer-web").orElseThrow();
        var population = client.population();
        for (var invalid : List.of(
                new TenantApplicationService.ClientAuthority(TENANT, SOURCE_AUDIENCE, client.clientType(),
                        client.scopes(), UUID.randomUUID(), population),
                new TenantApplicationService.ClientAuthority("foreign", SOURCE_AUDIENCE, client.clientType(),
                        client.scopes(), sourceApplicationId, population))) {
            when(applications.activeAuthority("card-customer-web")).thenReturn(Optional.of(invalid));
            assertThatThrownBy(() -> service.resolve(person, SOURCE_CLIENT, DESTINATION_AUDIENCE, Set.of(SCOPE)))
                    .isInstanceOf(OAuth2AuthenticationException.class);
        }
        when(applications.activeAuthority("card-customer-web")).thenReturn(Optional.empty());
        assertThatThrownBy(() -> service.resolve(person, SOURCE_CLIENT, DESTINATION_AUDIENCE, Set.of(SCOPE)))
                .isInstanceOf(OAuth2AuthenticationException.class);
        when(applications.activeAuthority("card-customer-web")).thenReturn(Optional.of(client));
        Jwt multiAudience = Jwt.withTokenValue("multi").headers(h -> h.putAll(person.getHeaders()))
                .claims(c -> c.putAll(person.getClaims())).audience(List.of(SOURCE_AUDIENCE, DESTINATION_AUDIENCE)).build();
        assertThatThrownBy(() -> service.resolve(multiAudience, SOURCE_CLIENT, DESTINATION_AUDIENCE, Set.of(SCOPE)))
                .isInstanceOf(OAuth2AuthenticationException.class);
    }

    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    void agentDestinationDoesNotBecomeADirectPersonExchangePath(boolean customer) {
        Jwt person = personResourceSubject(customer);
        // setUp supplies only an AGENT route to this audience.
        assertThatThrownBy(() -> service.resolve(person, SOURCE_CLIENT, DESTINATION_AUDIENCE, Set.of(SCOPE)))
                .isInstanceOf(OAuth2AuthenticationException.class)
                .satisfies(error -> assertThat(((OAuth2AuthenticationException) error).getError().getErrorCode())
                        .isEqualTo("invalid_target"));
    }

    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    void resourceScopeIntersectionIncludesTheActorClient(boolean customer) {
        Jwt person = personResourceSubject(customer);
        resourceRoutes(resourceRoute(NOW.plusSeconds(600)));
        when(applications.activeAuthority(SOURCE_CLIENT)).thenReturn(Optional.of(new TenantApplicationService.ClientAuthority(
                TENANT, SOURCE_AUDIENCE, TenantApplicationClient.Type.CONFIDENTIAL_SERVICE, List.of(), sourceApplicationId)));
        assertThatThrownBy(() -> service.resolve(person, SOURCE_CLIENT, DESTINATION_AUDIENCE, Set.of(SCOPE)))
                .isInstanceOf(OAuth2AuthenticationException.class)
                .satisfies(error -> assertThat(((OAuth2AuthenticationException) error).getError().getErrorCode())
                        .isEqualTo("invalid_scope"));
    }

    private Jwt personResourceSubject(boolean customer) {
        when(applications.isActiveAudience(TENANT, DESTINATION_AUDIENCE)).thenReturn(true);
        if (!customer) {
            when(applicationAccess.decisionAuthority(TENANT, sourceApplicationId, "meridian-1008"))
                    .thenReturn(Optional.of(new ApplicationAccessService.DecisionAuthority(
                            "cards", 7, Set.of("operator"), Map.of(SCOPE, "allow"), Map.of(), "v1")));
            return token("meridian-1008", SOURCE_AUDIENCE, Map.of("tenant_id", TENANT,
                    "identity_kind", "workforce", "client_id", "card-customer-web", "scope", SCOPE));
        }
        var customers = mock(com.openwolf.iam.repository.CustomerIdentityRepository.class);
        service.setCustomers(customers);
        var person = new com.openwolf.iam.entity.CustomerIdentity(TENANT, "person@example.invalid", "Person", "hash", NOW);
        person.verify(NOW);
        when(customers.findByTenantIdAndId(TENANT, person.getId())).thenReturn(Optional.of(person));
        when(applications.activeAuthority("card-customer-web")).thenReturn(Optional.of(new TenantApplicationService.ClientAuthority(
                TENANT, SOURCE_AUDIENCE, TenantApplicationClient.Type.PUBLIC_BROWSER, List.of(SCOPE), sourceApplicationId,
                TenantApplicationClient.Population.CUSTOMER)));
        return token(person.getId().toString(), SOURCE_AUDIENCE, Map.of("tenant_id", TENANT,
                "identity_kind", "customer", "client_id", "card-customer-web", "scope", SCOPE,
                "token_version", person.getTokenVersion()));
    }

    private AgentExchangeRoute resourceRoute(Instant expiry) {
        return new AgentExchangeRoute(TENANT, source.getId(), AgentExchangeRoute.DestinationType.RESOURCE,
                null, DESTINATION_AUDIENCE, List.of(SCOPE), "Read resource", expiry, NOW);
    }

    private void resourceRoutes(AgentExchangeRoute... values) {
        when(routes.findByTenantIdAndSourceWorkloadIdAndAudienceAndStatus(
                TENANT, source.getId(), DESTINATION_AUDIENCE, AgentExchangeRoute.Status.ACTIVE))
                .thenReturn(List.of(values));
    }

    private TenantApplicationService.ClientAuthority authority(
            String audience, TenantApplicationClient.Type type, UUID applicationId) {
        return new TenantApplicationService.ClientAuthority(TENANT, audience, type, List.of(SCOPE), applicationId);
    }

    private Jwt gatewayAuthorization(String tenantId) {
        return gatewayAuthorizationWithActor(tenantId, actor(source));
    }

    private Jwt gatewayAuthorizationWithActor(Map<String, Object> actor) {
        return gatewayAuthorizationWithActor(TENANT, actor);
    }

    private Jwt gatewayAuthorizationWithActor(String tenantId, Map<String, Object> actor) {
        return token("meridian-1008", GATEWAY_AUDIENCE, Map.of(
                "tenant_id", tenantId,
                "identity_kind", "workforce",
                "client_id", SOURCE_CLIENT,
                "scope", SCOPE,
                "token_use", "gateway_authorization",
                "authority_profile", "workload_continuation",
                "authority_id", gatewayRoute.getId().toString(),
                "act", actor));
    }

    private static Map<String, Object> actor(AgentWorkloadIdentity workload) {
        return Map.of("sub", workload.getWorkloadRef(), "client_id", workload.getOauthClientId(),
                "workload_id", workload.getId().toString());
    }

    private static Jwt token(String subject, String audience, Map<String, Object> claims) {
        Jwt.Builder builder = Jwt.withTokenValue(UUID.randomUUID().toString())
                .header("alg", "RS256")
                .subject(subject)
                .issuedAt(NOW.minusSeconds(30))
                .expiresAt(NOW.plusSeconds(600))
                .audience(List.of(audience));
        claims.forEach(builder::claim);
        return builder.build();
    }
}
