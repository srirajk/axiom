package com.openwolf.iam.repository;

import com.openwolf.iam.entity.AgentWorkloadIdentity;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

public interface AgentWorkloadIdentityRepository extends JpaRepository<AgentWorkloadIdentity, UUID> {
    Optional<AgentWorkloadIdentity> findByTenantIdAndId(String tenantId, UUID id);
    Optional<AgentWorkloadIdentity> findByOauthClientId(String oauthClientId);
    Optional<AgentWorkloadIdentity> findByTenantIdAndWorkloadRef(String tenantId, String workloadRef);
    boolean existsByTenantIdAndWorkloadRef(String tenantId, String workloadRef);
    boolean existsByTenantIdAndOauthClientId(String tenantId, String oauthClientId);
    List<AgentWorkloadIdentity> findByTenantIdOrderByCreatedAtAsc(String tenantId);
}
