package com.openwolf.iam.authority.consent;

import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

public interface AgentWorkloadPurposeRepository extends JpaRepository<AgentWorkloadPurpose, UUID> {
    Optional<AgentWorkloadPurpose> findByTenantIdAndAgentWorkloadIdAndPurposeCode(String tenantId, UUID workloadId,
                                                                                String purposeCode);

    Optional<AgentWorkloadPurpose> findByTenantIdAndAgentWorkloadIdAndId(String tenantId, UUID workloadId, UUID id);

    List<AgentWorkloadPurpose> findByTenantIdAndAgentWorkloadIdOrderByCreatedAtAsc(String tenantId, UUID workloadId);
}
