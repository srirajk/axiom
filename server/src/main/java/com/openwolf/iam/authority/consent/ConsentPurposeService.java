package com.openwolf.iam.authority.consent;

import com.openwolf.iam.auth.BusinessScopeRegistry;
import com.openwolf.iam.entity.AgentWorkloadIdentity;
import com.openwolf.iam.entity.TenantApplicationClient;
import com.openwolf.iam.exception.EntityNotFoundException;
import com.openwolf.iam.exception.ResourceConflictException;
import com.openwolf.iam.repository.AgentWorkloadIdentityRepository;
import com.openwolf.iam.service.CiamLifecycleAuditService;
import com.openwolf.iam.service.TenantApplicationService;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.TreeSet;
import java.util.UUID;

/**
 * Phase 3.2 purpose registry. A purpose is the only structured statement of why an Agent may act for a customer;
 * the purpose text a customer sees is description, never authority.
 */
@Service
@Transactional
public class ConsentPurposeService {
    public static final Duration MAX_VALIDITY = Duration.ofDays(90);

    public record PurposeView(UUID id, UUID agentWorkloadId, String purposeCode, String description,
                              List<String> allowedScopes, long maxValiditySeconds, AgentWorkloadPurpose.Status status,
                              Instant createdAt, Instant retiredAt, long revision) {}

    private final AgentWorkloadPurposeRepository purposes;
    private final AgentWorkloadIdentityRepository workloads;
    private final TenantApplicationService applications;
    private final BusinessScopeRegistry businessScopes;
    private final CiamLifecycleAuditService audit;
    private final Clock clock = Clock.systemUTC();

    public ConsentPurposeService(AgentWorkloadPurposeRepository purposes, AgentWorkloadIdentityRepository workloads,
                                 TenantApplicationService applications, BusinessScopeRegistry businessScopes,
                                 CiamLifecycleAuditService audit) {
        this.purposes = purposes; this.workloads = workloads; this.applications = applications;
        this.businessScopes = businessScopes; this.audit = audit;
    }

    public PurposeView register(String tenantId, UUID workloadId, String purposeCode, String description,
                                Collection<String> scopes, long maxValiditySeconds, String actorId) {
        AgentWorkloadIdentity workload = workloads.findByTenantIdAndId(tenantId, workloadId)
                .filter(value -> value.getStatus() == AgentWorkloadIdentity.Status.ACTIVE)
                .orElseThrow(() -> new EntityNotFoundException("active agent workload identity not found"));
        String code = purposeCode == null ? "" : purposeCode.trim();
        if (!code.matches("[a-z][a-z0-9._-]{1,63}")) throw new IllegalArgumentException("purpose code is malformed");
        Duration validity = Duration.ofSeconds(maxValiditySeconds);
        if (validity.isNegative() || validity.isZero() || validity.compareTo(MAX_VALIDITY) > 0) {
            throw new IllegalArgumentException("purpose validity must be between one second and 90 days");
        }
        TreeSet<String> normalized = new TreeSet<>();
        for (String scope : scopes) normalized.add(scope.trim());
        var client = applications.activeAuthority(workload.getOauthClientId())
                .filter(value -> value.tenantId().equals(tenantId))
                .filter(value -> value.clientType() == TenantApplicationClient.Type.CONFIDENTIAL_SERVICE)
                .orElseThrow(() -> new ResourceConflictException("agent workload client is not active"));
        if (normalized.isEmpty() || normalized.stream().anyMatch(s -> s.isBlank() || !businessScopes.isApproved(s))
                || !client.scopes().containsAll(normalized)) {
            throw new IllegalArgumentException("purpose scopes must be approved scopes of the workload client");
        }
        if (purposes.findByTenantIdAndAgentWorkloadIdAndPurposeCode(tenantId, workloadId, code).isPresent()) {
            throw new ResourceConflictException("purpose code already registered for this workload");
        }
        AgentWorkloadPurpose purpose = purposes.save(new AgentWorkloadPurpose(tenantId, workloadId, code,
                description.trim(), List.copyOf(normalized), validity, clock.instant()));
        audit.record(tenantId, actorId, "CONSENT_PURPOSE_REGISTERED", "agent_workload_purpose",
                purpose.getId().toString(), Map.of("workloadId", workloadId.toString(), "purposeCode", code,
                        "scopes", normalized, "maxValiditySeconds", maxValiditySeconds), purpose.getId().toString());
        return view(purpose);
    }

    /** Retiring a purpose stops every grant made under it at its next use (checked live, never cached). */
    public PurposeView retire(String tenantId, UUID workloadId, UUID purposeId, String actorId) {
        AgentWorkloadPurpose purpose = purposes.findByTenantIdAndAgentWorkloadIdAndId(tenantId, workloadId, purposeId)
                .orElseThrow(() -> new EntityNotFoundException("purpose not found"));
        boolean changed = purpose.getStatus() == AgentWorkloadPurpose.Status.ACTIVE;
        purpose.retire(clock.instant());
        if (changed) {
            audit.record(tenantId, actorId, "CONSENT_PURPOSE_RETIRED", "agent_workload_purpose",
                    purposeId.toString(), Map.of("purposeCode", purpose.getPurposeCode()), purposeId.toString());
        }
        return view(purpose);
    }

    @Transactional(readOnly = true)
    public List<PurposeView> list(String tenantId, UUID workloadId) {
        return purposes.findByTenantIdAndAgentWorkloadIdOrderByCreatedAtAsc(tenantId, workloadId).stream()
                .map(ConsentPurposeService::view).toList();
    }

    /** The active purpose a purpose-bound grant was made under, if it still exists and still covers its scopes. */
    @Transactional(readOnly = true)
    public Optional<AgentWorkloadPurpose> activePurpose(String tenantId, UUID workloadId, String purposeCode,
                                                        Set<String> scopes) {
        return purposes.findByTenantIdAndAgentWorkloadIdAndPurposeCode(tenantId, workloadId, purposeCode)
                .filter(value -> value.getStatus() == AgentWorkloadPurpose.Status.ACTIVE)
                .filter(value -> Set.copyOf(value.getAllowedScopes()).containsAll(scopes));
    }

    static PurposeView view(AgentWorkloadPurpose value) {
        return new PurposeView(value.getId(), value.getAgentWorkloadId(), value.getPurposeCode(),
                value.getDescription(), value.getAllowedScopes(), value.getMaxValidity().toSeconds(),
                value.getStatus(), value.getCreatedAt(), value.getRetiredAt(), value.getRevision());
    }
}
