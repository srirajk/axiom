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

    private com.openwolf.iam.authority.consent.ConsentPurposeService purposes;

    @org.springframework.beans.factory.annotation.Autowired(required = false)
    void setPurposes(com.openwolf.iam.authority.consent.ConsentPurposeService purposes) {
        this.purposes = purposes;
    }

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
        return requireAuthorized(tenantId, customerId, actorClientId, audience, requestedScopes, null, null);
    }

    /**
     * Phase 3.2: {@code requestedPurpose} (an exchange's {@code delegation_purpose}) restricts matching to grants
     * bound to that registered purpose; {@code grantId} (a token's {@code delegation_id}) restricts it to that exact
     * grant. A purpose-bound grant is usable only while its purpose is active and still covers its scopes. For a
     * purpose-bound grant the authorized {@code purpose} is the purpose code, never free text.
     */
    public AuthorizedDelegation requireAuthorized(String tenantId, UUID customerId,
                                                  String actorClientId, String audience,
                                                  Set<String> requestedScopes, String requestedPurpose,
                                                  UUID grantId) {
        CustomerIdentity customer = customers.requireCustomer(tenantId, customerId);
        if (customer.getStatus() != CustomerIdentity.Status.ACTIVE) return denied();
        Instant now = clock.instant();
        AuthorizedDelegation match = null;
        for (CustomerDelegationGrant grant : grants.findByTenantIdAndCustomerIdAndStatus(
                tenantId, customerId, CustomerDelegationGrant.Status.ACTIVE)) {
            AgentWorkloadIdentity workload = workloads.findByTenantIdAndId(tenantId, grant.getAgentWorkloadId())
                    .orElse(null);
            if (workload == null || !usable(workload)) continue;
            Set<String> grantedScopes = Set.copyOf(delegationService.readScopes(grant));
            if (grantId != null && !grantId.equals(grant.getId())) continue;
            if (requestedPurpose != null && !requestedPurpose.equals(grant.getPurposeCode())) continue;
            if (grant.getPurposeCode() != null && (purposes == null || purposes.activePurpose(tenantId,
                    workload.getId(), grant.getPurposeCode(), grantedScopes).isEmpty())) continue;
            if (workload.getOauthClientId().equals(actorClientId)
                    && grant.getAudience().equals(audience)
                    && grant.isUsableAt(now)
                    && grantedScopes.containsAll(requestedScopes)) {
                if (match != null) {
                    throw new ResourceConflictException("multiple active delegations match this exchange");
                }
                match = new AuthorizedDelegation(grant.getId(), customerId, workload.getId(),
                        workload.getWorkloadRef(), actorClientId, audience, grantedScopes,
                        grant.getPurposeCode() != null ? grant.getPurposeCode() : grant.getPurpose(),
                        grant.getConsentRecordedAt(), grant.getExpiresAt());
            }
        }
        if (match == null) return denied();
        return match;
    }

    private static AuthorizedDelegation denied() {
        throw new ResourceConflictException("no active customer delegation authorizes this exchange");
    }
}
