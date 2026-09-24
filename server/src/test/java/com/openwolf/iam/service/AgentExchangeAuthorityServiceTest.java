package com.openwolf.iam.service;

import com.openwolf.iam.auth.BusinessScopeRegistry;
import com.openwolf.iam.dto.AgentExchangeContracts.CreateAgentExchangeRouteRequest;
import com.openwolf.iam.entity.AgentExchangeRoute;
import com.openwolf.iam.entity.AgentWorkloadIdentity;
import com.openwolf.iam.entity.TenantApplicationClient;
import com.openwolf.iam.entity.TrustedExchangeBroker;
import com.openwolf.iam.repository.AgentExchangeRouteRepository;
import com.openwolf.iam.repository.AgentWorkloadIdentityRepository;
import com.openwolf.iam.repository.TrustedExchangeBrokerRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
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
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class AgentExchangeAuthorityServiceTest {
    private static final String TENANT = "meridian";
    private static final String SCOPE = "cards:incident.read";
    private static final String SOURCE_CLIENT = "card-assistance-agent";
    private static final String DESTINATION_CLIENT = "card-actions-agent";
    private static final String GATEWAY_CLIENT = "argus-gateway-broker";
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
        source = new AgentWorkloadIdentity(TENANT, "agent:card-assistance:development",
                "Card Assistance Agent", SOURCE_CLIENT, NOW);
        destination = new AgentWorkloadIdentity(TENANT, "agent:card-actions:development",
                "Card Actions Agent", DESTINATION_CLIENT, NOW);
        broker = new TrustedExchangeBroker(TENANT, GATEWAY_CLIENT, GATEWAY_AUDIENCE,
                List.of(SCOPE), NOW);
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

    private TenantApplicationService.ClientAuthority authority(
            String audience, TenantApplicationClient.Type type, UUID applicationId) {
        return new TenantApplicationService.ClientAuthority(TENANT, audience, type, List.of(SCOPE), applicationId);
    }

    private Jwt gatewayAuthorization(String tenantId) {
        return token("meridian-1008", GATEWAY_AUDIENCE, Map.of(
                "tenant_id", tenantId,
                "identity_kind", "workforce",
                "client_id", SOURCE_CLIENT,
                "scope", SCOPE,
                "token_use", "gateway_authorization",
                "authority_profile", "workload_continuation",
                "authority_id", gatewayRoute.getId().toString(),
                "act", actor(source)));
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
