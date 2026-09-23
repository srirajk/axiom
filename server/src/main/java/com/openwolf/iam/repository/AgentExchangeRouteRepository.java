package com.openwolf.iam.repository;

import com.openwolf.iam.entity.AgentExchangeRoute;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

public interface AgentExchangeRouteRepository extends JpaRepository<AgentExchangeRoute, UUID> {
    Optional<AgentExchangeRoute> findByTenantIdAndId(String tenantId, UUID id);
    List<AgentExchangeRoute> findByTenantIdAndSourceWorkloadIdAndAudienceAndStatus(
            String tenantId, UUID sourceWorkloadId, String audience, AgentExchangeRoute.Status status);
    List<AgentExchangeRoute> findByTenantIdOrderByCreatedAtAsc(String tenantId);
}
