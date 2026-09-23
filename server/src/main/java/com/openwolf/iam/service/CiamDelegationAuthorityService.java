package com.openwolf.iam.service;

import com.openwolf.iam.entity.AgentWorkloadIdentity;
import com.openwolf.iam.entity.CustomerDelegationGrant;
import com.openwolf.iam.entity.CustomerIdentity;
import com.openwolf.iam.exception.ResourceConflictException;
import com.openwolf.iam.repository.AgentWorkloadIdentityRepository;
import com.openwolf.iam.repository.CustomerDelegationGrantRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Clock;
import java.time.Instant;
import java.util.List;
import java.util.Set;
import java.util.UUID;

@Service
@Transactional(readOnly = true)
public class CiamDelegationAuthorityService {
    public record AuthorizedDelegation(UUID grantId, UUID customerId, UUID workloadId,
                                       String workloadRef, String actorClientId, String audience,
                                       Set<String> grantedScopes, String purpose,
                                       Instant consentRecordedAt, Instant expiresAt) {}

    private final CustomerDelegationGrantRepository grants;
    private final AgentWorkloadIdentityRepository workloads;
    private final CiamCustomerService customers;
    private final CiamDelegationService delegationService;
    private final Clock clock;

    @org.springframework.beans.factory.annotation.Autowired
    public CiamDelegationAuthorityService(CustomerDelegationGrantRepository grants,
                                          AgentWorkloadIdentityRepository workloads,
                                          CiamCustomerService customers,
                                          CiamDelegationService delegationService) {
        this(grants, workloads, customers, delegationService, Clock.systemUTC());
    }

    CiamDelegationAuthorityService(CustomerDelegationGrantRepository grants,
                                   AgentWorkloadIdentityRepository workloads,
                                   CiamCustomerService customers,
                                   CiamDelegationService delegationService, Clock clock) {
        this.grants = grants;
        this.workloads = workloads;
        this.customers = customers;
        this.delegationService = delegationService;
        this.clock = clock;
    }

    public AuthorizedDelegation requireAuthorized(String tenantId, UUID customerId,
                                                  String actorClientId, String audience,
                                                  Set<String> requestedScopes) {
        CustomerIdentity customer = customers.requireCustomer(tenantId, customerId);
        if (customer.getStatus() != CustomerIdentity.Status.ACTIVE) return denied();
        Instant now = clock.instant();
        AuthorizedDelegation match = null;
        for (CustomerDelegationGrant grant : grants.findByTenantIdAndCustomerIdAndStatus(
                tenantId, customerId, CustomerDelegationGrant.Status.ACTIVE)) {
            AgentWorkloadIdentity workload = workloads.findByTenantIdAndId(tenantId, grant.getAgentWorkloadId())
                    .orElse(null);
            if (workload == null || workload.getStatus() != AgentWorkloadIdentity.Status.ACTIVE) continue;
            Set<String> grantedScopes = Set.copyOf(delegationService.readScopes(grant));
            if (workload.getOauthClientId().equals(actorClientId)
                    && grant.getAudience().equals(audience)
                    && grant.isUsableAt(now)
                    && grantedScopes.containsAll(requestedScopes)) {
                if (match != null) {
                    throw new ResourceConflictException("multiple active delegations match this exchange");
                }
                match = new AuthorizedDelegation(grant.getId(), customerId, workload.getId(),
                        workload.getWorkloadRef(), actorClientId, audience, grantedScopes,
                        grant.getPurpose(), grant.getConsentRecordedAt(), grant.getExpiresAt());
            }
        }
        if (match == null) return denied();
        return match;
    }

    private static AuthorizedDelegation denied() {
        throw new ResourceConflictException("no active customer delegation authorizes this exchange");
    }
}
