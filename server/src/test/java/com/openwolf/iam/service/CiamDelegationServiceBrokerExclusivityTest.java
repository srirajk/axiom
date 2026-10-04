package com.openwolf.iam.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.openwolf.iam.auth.BusinessScopeRegistry;
import com.openwolf.iam.entity.AgentWorkloadIdentity;
import com.openwolf.iam.entity.TenantApplicationClient;
import com.openwolf.iam.entity.TrustedExchangeBroker;
import com.openwolf.iam.exception.ResourceConflictException;
import com.openwolf.iam.repository.AgentWorkloadIdentityRepository;
import com.openwolf.iam.repository.CustomerDelegationGrantRepository;
import com.openwolf.iam.repository.TrustedExchangeBrokerRepository;
import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class CiamDelegationServiceBrokerExclusivityTest {
    private static final String TENANT = "meridian";
    private static final String CLIENT = "argus-gateway-broker";
    private static final Instant NOW = Instant.parse("2026-10-02T00:00:00Z");

    private final AgentWorkloadIdentityRepository workloads = mock(AgentWorkloadIdentityRepository.class);
    private final TrustedExchangeBrokerRepository brokers = mock(TrustedExchangeBrokerRepository.class);
    private final TenantApplicationService applications = mock(TenantApplicationService.class);
    private final CiamDelegationService service = new CiamDelegationService(workloads, brokers,
            mock(CustomerDelegationGrantRepository.class), mock(CiamCustomerService.class),
            mock(CiamLifecycleAuditService.class), new ObjectMapper(), applications,
            new BusinessScopeRegistry("quickstart:invoke"), Clock.fixed(NOW, ZoneOffset.UTC));

    @Test
    void brokerRegisteredFirstCannotBecomeWorkload() {
        when(brokers.findByTenantIdAndOauthClientId(TENANT, CLIENT)).thenReturn(Optional.of(
                new TrustedExchangeBroker(TENANT, CLIENT, "argus-gateway",
                        List.of("quickstart:invoke"), NOW)));

        assertThatThrownBy(() -> service.registerWorkload(TENANT, "agent:gateway:development",
                "Gateway as Agent", CLIENT, "admin", "test"))
                .isInstanceOf(ResourceConflictException.class)
                .hasMessageContaining("broker cannot be an Agent workload");
        var order = inOrder(applications, brokers);
        order.verify(applications).lockClientForIdentityRegistration(CLIENT);
        order.verify(brokers).findByTenantIdAndOauthClientId(TENANT, CLIENT);
        verify(workloads, never()).save(any(AgentWorkloadIdentity.class));
    }

    @Test
    void independentConfidentialClientCanStillBecomeWorkload() {
        when(applications.activeAuthority(CLIENT)).thenReturn(Optional.of(
                new TenantApplicationService.ClientAuthority(TENANT, "agent-api",
                        TenantApplicationClient.Type.CONFIDENTIAL_SERVICE,
                        List.of("quickstart:invoke"), UUID.randomUUID())));
        when(workloads.save(any(AgentWorkloadIdentity.class))).thenAnswer(call -> call.getArgument(0));

        var created = service.registerWorkload(TENANT, "agent:worker:development",
                "Worker", CLIENT, "admin", "test");

        assertThat(created.oauthClientId()).isEqualTo(CLIENT);
        verify(workloads).save(any(AgentWorkloadIdentity.class));
    }
}
