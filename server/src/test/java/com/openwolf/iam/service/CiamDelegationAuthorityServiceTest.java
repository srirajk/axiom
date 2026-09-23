package com.openwolf.iam.service;

import com.openwolf.iam.entity.AgentWorkloadIdentity;
import com.openwolf.iam.entity.CustomerDelegationGrant;
import com.openwolf.iam.entity.CustomerIdentity;
import com.openwolf.iam.exception.ResourceConflictException;
import com.openwolf.iam.repository.AgentWorkloadIdentityRepository;
import com.openwolf.iam.repository.CustomerDelegationGrantRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Optional;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class CiamDelegationAuthorityServiceTest {
    private static final Instant NOW = Instant.parse("2026-09-19T10:00:00Z");
    private final CustomerDelegationGrantRepository grants = mock(CustomerDelegationGrantRepository.class);
    private final AgentWorkloadIdentityRepository workloads = mock(AgentWorkloadIdentityRepository.class);
    private final CiamCustomerService customers = mock(CiamCustomerService.class);
    private final CiamDelegationService delegationService = mock(CiamDelegationService.class);
    private CiamDelegationAuthorityService service;
    private CustomerIdentity customer;
    private AgentWorkloadIdentity workload;
    private CustomerDelegationGrant grant;

    @BeforeEach
    void setUp() {
        service = new CiamDelegationAuthorityService(grants, workloads, customers, delegationService,
                Clock.fixed(NOW, ZoneOffset.UTC));
        customer = new CustomerIdentity("tenant-1", "customer@example.com", "Customer", "hash", NOW);
        customer.verify(NOW);
        workload = new AgentWorkloadIdentity("tenant-1", "agent:card-triage", "Card Triage",
                "card-triage-client", NOW);
        grant = new CustomerDelegationGrant("tenant-1", customer.getId(), workload.getId(),
                "cards-api", "[\"cards:read\",\"cards:report\"]", "report a lost card",
                NOW.plusSeconds(600), NOW);
        when(customers.requireCustomer("tenant-1", customer.getId())).thenReturn(customer);
        when(workloads.findByTenantIdAndId("tenant-1", workload.getId())).thenReturn(Optional.of(workload));
        when(delegationService.readScopes(grant)).thenReturn(List.of("cards:read", "cards:report"));
    }

    @Test
    void derivesGrantAndPurposeFromOneExactPersistedAuthority() {
        when(grants.findByTenantIdAndCustomerIdAndStatus("tenant-1", customer.getId(),
                CustomerDelegationGrant.Status.ACTIVE)).thenReturn(List.of(grant));

        var result = service.requireAuthorized("tenant-1", customer.getId(), "card-triage-client",
                "cards-api", Set.of("cards:read"));

        assertThat(result.grantId()).isEqualTo(grant.getId());
        assertThat(result.purpose()).isEqualTo("report a lost card");
        assertThat(result.grantedScopes()).containsExactlyInAnyOrder("cards:read", "cards:report");
    }

    @Test
    void rejectsMissingExcessScopeAndAmbiguousAuthority() {
        when(grants.findByTenantIdAndCustomerIdAndStatus("tenant-1", customer.getId(),
                CustomerDelegationGrant.Status.ACTIVE)).thenReturn(List.of(grant));
        assertThatThrownBy(() -> service.requireAuthorized("tenant-1", customer.getId(),
                "card-triage-client", "cards-api", Set.of("cards:write")))
                .isInstanceOf(ResourceConflictException.class);

        CustomerDelegationGrant duplicate = new CustomerDelegationGrant("tenant-1", customer.getId(),
                workload.getId(), "cards-api", "[\"cards:read\"]", "duplicate",
                NOW.plusSeconds(600), NOW);
        when(delegationService.readScopes(duplicate)).thenReturn(List.of("cards:read"));
        when(grants.findByTenantIdAndCustomerIdAndStatus("tenant-1", customer.getId(),
                CustomerDelegationGrant.Status.ACTIVE)).thenReturn(List.of(grant, duplicate));
        assertThatThrownBy(() -> service.requireAuthorized("tenant-1", customer.getId(),
                "card-triage-client", "cards-api", Set.of("cards:read")))
                .isInstanceOf(ResourceConflictException.class)
                .hasMessageContaining("multiple");
    }
}
