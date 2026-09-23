package com.openwolf.iam.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.openwolf.iam.dto.CiamContracts.AgentWorkloadResponse;
import com.openwolf.iam.dto.CiamContracts.AgentWorkloadConsentOption;
import com.openwolf.iam.dto.CiamContracts.DelegationGrantResponse;
import com.openwolf.iam.entity.AgentWorkloadIdentity;
import com.openwolf.iam.entity.CustomerDelegationGrant;
import com.openwolf.iam.entity.CustomerIdentity;
import com.openwolf.iam.entity.TenantApplicationClient;
import com.openwolf.iam.auth.BusinessScopeRegistry;
import com.openwolf.iam.exception.EntityNotFoundException;
import com.openwolf.iam.exception.ResourceConflictException;
import com.openwolf.iam.repository.AgentWorkloadIdentityRepository;
import com.openwolf.iam.repository.CustomerDelegationGrantRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.UUID;

@Service
@Transactional
public class CiamDelegationService {
    private static final Duration MAX_GRANT_LIFETIME = Duration.ofDays(90);
    private final AgentWorkloadIdentityRepository workloads;
    private final CustomerDelegationGrantRepository grants;
    private final CiamCustomerService customers;
    private final CiamLifecycleAuditService audit;
    private final ObjectMapper objectMapper;
    private final Clock clock;
    private final TenantApplicationService applications;
    private final BusinessScopeRegistry businessScopes;

    @org.springframework.beans.factory.annotation.Autowired
    public CiamDelegationService(AgentWorkloadIdentityRepository workloads,
                                 CustomerDelegationGrantRepository grants,
                                 CiamCustomerService customers, CiamLifecycleAuditService audit,
                                 ObjectMapper objectMapper, TenantApplicationService applications,
                                 BusinessScopeRegistry businessScopes) {
        this(workloads, grants, customers, audit, objectMapper, applications,
                businessScopes, Clock.systemUTC());
    }

    CiamDelegationService(AgentWorkloadIdentityRepository workloads,
                          CustomerDelegationGrantRepository grants,
                          CiamCustomerService customers, CiamLifecycleAuditService audit,
                          ObjectMapper objectMapper, TenantApplicationService applications,
                          BusinessScopeRegistry businessScopes, Clock clock) {
        this.workloads = workloads;
        this.grants = grants;
        this.customers = customers;
        this.audit = audit;
        this.objectMapper = objectMapper;
        this.applications = applications;
        this.businessScopes = businessScopes;
        this.clock = clock;
    }

    public AgentWorkloadResponse registerWorkload(String tenantId, String workloadRef, String name,
                                                   String oauthClientId, String actorId,
                                                   String correlationId) {
        var clientAuthority = applications.activeAuthority(oauthClientId)
                .filter(value -> value.tenantId().equals(tenantId))
                .filter(value -> value.clientType() == TenantApplicationClient.Type.CONFIDENTIAL_SERVICE)
                .orElseThrow(() -> new IllegalArgumentException(
                        "agent workload requires an active same-tenant confidential service client"));
        if (workloads.existsByTenantIdAndWorkloadRef(tenantId, workloadRef)) {
            throw new ResourceConflictException("agent workload reference already exists");
        }
        if (workloads.existsByTenantIdAndOauthClientId(tenantId, oauthClientId)) {
            throw new ResourceConflictException("agent OAuth client is already registered");
        }
        AgentWorkloadIdentity workload = workloads.save(new AgentWorkloadIdentity(tenantId,
                workloadRef.trim(), name.trim(), oauthClientId.trim(), clock.instant()));
        audit.record(tenantId, actorId, "AGENT_WORKLOAD_REGISTERED", "agent_workload_identity",
                workload.getId().toString(), Map.of("workloadRef", workload.getWorkloadRef(),
                        "oauthClientId", workload.getOauthClientId()), correlationId);
        return toResponse(workload);
    }

    @Transactional(readOnly = true)
    public List<AgentWorkloadResponse> listWorkloads(String tenantId) {
        return workloads.findByTenantIdOrderByCreatedAtAsc(tenantId).stream().map(CiamDelegationService::toResponse).toList();
    }

    @Transactional(readOnly = true)
    public List<AgentWorkloadConsentOption> listConsentOptions(String tenantId) {
        return workloads.findByTenantIdOrderByCreatedAtAsc(tenantId).stream()
                .filter(value -> value.getStatus() == AgentWorkloadIdentity.Status.ACTIVE)
                .map(value -> applications.activeAuthority(value.getOauthClientId())
                        .filter(authority -> authority.tenantId().equals(tenantId))
                        .filter(authority -> authority.clientType() == TenantApplicationClient.Type.CONFIDENTIAL_SERVICE)
                        .map(authority -> new AgentWorkloadConsentOption(value.getId(), value.getWorkloadRef(),
                                value.getName(), authority.audience(), authority.scopes().stream()
                                .filter(businessScopes::isApproved).sorted().toList()))
                        .orElse(null))
                .filter(java.util.Objects::nonNull)
                .toList();
    }

    public AgentWorkloadResponse revokeWorkload(String tenantId, UUID workloadId, String actorId,
                                                 String correlationId) {
        AgentWorkloadIdentity workload = requireWorkload(tenantId, workloadId);
        Instant now = clock.instant();
        boolean changed = workload.getStatus() != AgentWorkloadIdentity.Status.REVOKED;
        workload.revoke(now);
        if (!changed) return toResponse(workload);
        grants.findByTenantIdAndAgentWorkloadIdAndStatus(tenantId, workloadId,
                CustomerDelegationGrant.Status.ACTIVE).forEach(grant -> {
                    grant.revoke("agent workload revoked", now);
                    audit.record(tenantId, actorId, "DELEGATION_GRANT_REVOKED", "delegation_grant",
                            grant.getId().toString(), Map.of("reason", "agent workload revoked"), correlationId);
                });
        audit.record(tenantId, actorId, "AGENT_WORKLOAD_REVOKED", "agent_workload_identity",
                workloadId.toString(), Map.of("workloadRef", workload.getWorkloadRef()), correlationId);
        return toResponse(workload);
    }

    public DelegationGrantResponse createGrant(String tenantId, UUID customerId, UUID workloadId,
                                                String audience, Set<String> scopes, String purpose,
                                                Instant expiresAt, String actorId, String correlationId) {
        CustomerIdentity customer = customers.requireCustomer(tenantId, customerId);
        if (customer.getStatus() != CustomerIdentity.Status.ACTIVE) {
            throw new ResourceConflictException("customer must be active and verified");
        }
        AgentWorkloadIdentity workload = requireWorkload(tenantId, workloadId);
        if (workload.getStatus() != AgentWorkloadIdentity.Status.ACTIVE) {
            throw new ResourceConflictException("agent workload is not active");
        }
        Instant now = clock.instant();
        if (!expiresAt.isAfter(now) || expiresAt.isAfter(now.plus(MAX_GRANT_LIFETIME))) {
            throw new IllegalArgumentException("delegation expiry must be within 90 days");
        }
        TreeSet<String> normalizedScopes = new TreeSet<>();
        for (String scope : scopes) normalizedScopes.add(scope.trim());
        if (normalizedScopes.stream().anyMatch(String::isBlank)) {
            throw new IllegalArgumentException("delegation scopes cannot be blank");
        }
        var clientAuthority = applications.activeAuthority(workload.getOauthClientId())
                .filter(value -> value.tenantId().equals(tenantId))
                .filter(value -> value.clientType() == TenantApplicationClient.Type.CONFIDENTIAL_SERVICE)
                .orElseThrow(() -> new ResourceConflictException("agent workload client is not active"));
        if (!clientAuthority.audience().equals(audience.trim())
                || !clientAuthority.scopes().containsAll(normalizedScopes)
                || normalizedScopes.stream().anyMatch(scope -> !businessScopes.isApproved(scope))) {
            throw new IllegalArgumentException("delegation audience or scopes exceed the registered agent client authority");
        }
        CustomerDelegationGrant grant = grants.save(new CustomerDelegationGrant(tenantId, customerId,
                workloadId, audience.trim(), writeScopes(normalizedScopes), purpose.trim(), expiresAt, now));
        audit.record(tenantId, actorId, "DELEGATION_GRANT_CREATED", "delegation_grant",
                grant.getId().toString(), Map.of("customerId", customerId, "workloadId", workloadId,
                        "audience", grant.getAudience(), "scopes", normalizedScopes,
                        "expiresAt", expiresAt.toString()), correlationId);
        return toResponse(grant);
    }

    @Transactional(readOnly = true)
    public List<DelegationGrantResponse> listGrants(String tenantId, UUID customerId) {
        customers.requireCustomer(tenantId, customerId);
        return grants.findByTenantIdAndCustomerIdOrderByCreatedAtDesc(tenantId, customerId).stream()
                .map(this::toResponse).toList();
    }

    @Transactional(readOnly = true)
    public List<DelegationGrantResponse> listAllGrants(String tenantId) {
        return grants.findByTenantIdOrderByCreatedAtDesc(tenantId).stream()
                .map(this::toResponse).toList();
    }

    public DelegationGrantResponse revokeGrant(String tenantId, UUID customerId, UUID grantId,
                                                String reason, String actorId, String correlationId) {
        CustomerDelegationGrant grant = grants.findByTenantIdAndCustomerIdAndId(tenantId, customerId, grantId)
                .orElseThrow(() -> new EntityNotFoundException("delegation grant not found"));
        boolean changed = grant.getStatus() != CustomerDelegationGrant.Status.REVOKED;
        grant.revoke(reason.trim(), clock.instant());
        if (changed) {
            audit.record(tenantId, actorId, "DELEGATION_GRANT_REVOKED", "delegation_grant",
                    grantId.toString(), Map.of("reason", reason.trim()), correlationId);
        }
        return toResponse(grant);
    }

    AgentWorkloadIdentity requireWorkload(String tenantId, UUID workloadId) {
        return workloads.findByTenantIdAndId(tenantId, workloadId)
                .orElseThrow(() -> new EntityNotFoundException("agent workload identity not found"));
    }

    private String writeScopes(Set<String> scopes) {
        try { return objectMapper.writeValueAsString(scopes); }
        catch (JsonProcessingException ex) { throw new IllegalStateException("delegation scopes could not be serialized", ex); }
    }

    List<String> readScopes(CustomerDelegationGrant grant) {
        try {
            List<String> values = objectMapper.readValue(grant.getScopes(), new TypeReference<>() {});
            ArrayList<String> sorted = new ArrayList<>(values);
            sorted.sort(Comparator.naturalOrder());
            return List.copyOf(sorted);
        } catch (JsonProcessingException ex) {
            throw new IllegalStateException("persisted delegation scopes are invalid", ex);
        }
    }

    private static AgentWorkloadResponse toResponse(AgentWorkloadIdentity value) {
        return new AgentWorkloadResponse(value.getId(), value.getWorkloadRef(), value.getName(),
                value.getOauthClientId(), value.getStatus(), value.getCreatedAt(), value.getRevokedAt(),
                value.getRevision());
    }

    private DelegationGrantResponse toResponse(CustomerDelegationGrant value) {
        return new DelegationGrantResponse(value.getId(), value.getCustomerId(), value.getAgentWorkloadId(),
                value.getAudience(), readScopes(value), value.getPurpose(), value.getStatus(),
                value.getConsentRecordedAt(), value.getExpiresAt(), value.getRevokedAt(),
                value.getRevocationReason(), value.getRevision());
    }
}
