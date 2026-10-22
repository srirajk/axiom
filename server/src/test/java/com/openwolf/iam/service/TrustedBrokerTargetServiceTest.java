package com.openwolf.iam.service;

import com.openwolf.iam.auth.BusinessScopeRegistry;
import com.openwolf.iam.dto.AgentExchangeContracts.CreateBrokerTargetRequest;
import com.openwolf.iam.entity.AgentExchangeRoute;
import com.openwolf.iam.entity.AgentWorkloadIdentity;
import com.openwolf.iam.entity.TenantApplicationClient;
import com.openwolf.iam.entity.TrustedExchangeBroker;
import com.openwolf.iam.entity.TrustedExchangeBrokerTarget;
import com.openwolf.iam.repository.AgentWorkloadIdentityRepository;
import com.openwolf.iam.repository.TrustedExchangeBrokerRepository;
import com.openwolf.iam.repository.TrustedExchangeBrokerTargetRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class TrustedBrokerTargetServiceTest {
    private static final String TENANT = "meridian";
    private static final String SCOPE = "example:read";
    private static final String BROKER_SCOPE = "gateway:exchange";
    private static final String AUDIENCE = "orders-api";
    private static final Instant NOW = Instant.parse("2026-10-08T12:00:00Z");

    private final TrustedExchangeBrokerTargetRepository targets = mock(TrustedExchangeBrokerTargetRepository.class);
    private final TrustedExchangeBrokerRepository brokers = mock(TrustedExchangeBrokerRepository.class);
    private final AgentWorkloadIdentityRepository workloads = mock(AgentWorkloadIdentityRepository.class);
    private final TenantApplicationService applications = mock(TenantApplicationService.class);
    private final CiamLifecycleAuditService audit = mock(CiamLifecycleAuditService.class);
    private TrustedBrokerTargetService service;
    private TrustedExchangeBroker broker;

    @BeforeEach
    void setUp() {
        service = new TrustedBrokerTargetService(targets, brokers, workloads, applications,
                audit, new BusinessScopeRegistry(SCOPE), Clock.fixed(NOW, ZoneOffset.UTC));
        broker = new TrustedExchangeBroker(TENANT, "broker-client", "gateway-api", List.of(BROKER_SCOPE), NOW);
        when(brokers.findById(broker.getId())).thenReturn(Optional.of(broker));
        when(applications.activeAuthority("broker-client")).thenReturn(Optional.of(
                new TenantApplicationService.ClientAuthority(TENANT, "gateway-api",
                        TenantApplicationClient.Type.CONFIDENTIAL_SERVICE, List.of(BROKER_SCOPE), UUID.randomUUID())));
        when(applications.isActiveAudience(TENANT, AUDIENCE)).thenReturn(true);
        when(targets.save(any(TrustedExchangeBrokerTarget.class))).thenAnswer(call -> call.getArgument(0));
    }

    @Test
    void registeredResourceTargetIsBrokerScopedAndAudited() {
        var created = service.create(TENANT, broker.getId(), new CreateBrokerTargetRequest(AUDIENCE,
                AgentExchangeRoute.DestinationType.RESOURCE, null, Set.of(SCOPE), "Orders lookup"),
                "admin", "request-1");
        assertThat(created.brokerId()).isEqualTo(broker.getId());
        assertThat(created.audience()).isEqualTo(AUDIENCE);
        verify(audit).record(org.mockito.ArgumentMatchers.eq(TENANT), org.mockito.ArgumentMatchers.eq("admin"),
                org.mockito.ArgumentMatchers.eq("TRUSTED_EXCHANGE_BROKER_TARGET_CREATED"),
                org.mockito.ArgumentMatchers.eq("trusted_exchange_broker_target"), any(), any(),
                org.mockito.ArgumentMatchers.eq("request-1"));
    }

    @Test
    void unknownOrGatewayTargetAndExcessScopeAreDenied() {
        assertThatThrownBy(() -> service.create(TENANT, broker.getId(), new CreateBrokerTargetRequest(
                "unknown-api", AgentExchangeRoute.DestinationType.RESOURCE, null, Set.of(SCOPE), "Unknown"),
                "admin", null)).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> service.create(TENANT, broker.getId(), new CreateBrokerTargetRequest(
                "gateway-api", AgentExchangeRoute.DestinationType.RESOURCE, null, Set.of(SCOPE), "Gateway"),
                "admin", null)).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> service.create(TENANT, broker.getId(), new CreateBrokerTargetRequest(
                AUDIENCE, AgentExchangeRoute.DestinationType.RESOURCE, null, Set.of("outside:scope"), "Wider"),
                "admin", null)).isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void destinationBusinessScopesDoNotNeedToBeRegisteredOnBrokerClient() {
        service = new TrustedBrokerTargetService(targets, brokers, workloads, applications,
                audit, new BusinessScopeRegistry(SCOPE + "," + BROKER_SCOPE), Clock.fixed(NOW, ZoneOffset.UTC));
        var created = service.create(TENANT, broker.getId(), new CreateBrokerTargetRequest(
                AUDIENCE, AgentExchangeRoute.DestinationType.RESOURCE, null, Set.of(SCOPE), "Orders lookup"),
                "admin", null);
        assertThat(created.scopes()).containsExactly(SCOPE);
        assertThat(broker.getAllowedScopes()).containsExactly(BROKER_SCOPE);
    }

    @Test
    void revokedTargetBlocksLegacyFallbackAndOldToken() {
        TrustedExchangeBrokerTarget revoked = new TrustedExchangeBrokerTarget(broker.getId(), TENANT,
                AUDIENCE, AgentExchangeRoute.DestinationType.RESOURCE, null, List.of(SCOPE), "Orders", NOW);
        revoked.revoke(NOW.plusSeconds(1));
        when(targets.findByTenantIdAndBrokerIdAndAudienceOrderByCreatedAtDesc(TENANT, broker.getId(), AUDIENCE))
                .thenReturn(List.of(revoked));
        when(targets.findByTenantIdAndBrokerIdAndId(TENANT, broker.getId(), revoked.getId()))
                .thenReturn(Optional.of(revoked));

        assertThatThrownBy(() -> service.resolve(TENANT, broker.getId(), AUDIENCE))
                .isInstanceOf(OAuth2AuthenticationException.class)
                .satisfies(error -> assertThat(((OAuth2AuthenticationException) error).getError().getErrorCode())
                        .isEqualTo("invalid_target"));
        assertThatThrownBy(() -> service.requireActive(TENANT, broker.getId(), revoked.getId()))
                .isInstanceOf(OAuth2AuthenticationException.class);
    }

    @Test
    void agentTargetMustMatchActiveDestinationAudience() {
        AgentWorkloadIdentity destination = new AgentWorkloadIdentity(TENANT, "orders-worker", "Orders",
                "orders-client", NOW);
        when(workloads.findByTenantIdAndId(TENANT, destination.getId())).thenReturn(Optional.of(destination));
        when(applications.activeAuthority("orders-client")).thenReturn(Optional.of(
                new TenantApplicationService.ClientAuthority(TENANT, "wrong-api",
                        TenantApplicationClient.Type.CONFIDENTIAL_SERVICE, List.of(SCOPE), UUID.randomUUID())));
        assertThatThrownBy(() -> service.create(TENANT, broker.getId(), new CreateBrokerTargetRequest(
                AUDIENCE, AgentExchangeRoute.DestinationType.AGENT, destination.getId(), Set.of(SCOPE), "Orders"),
                "admin", null)).isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("destination workload authority");
    }
}
