package com.openwolf.iam.authority.task;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.Optional;
import java.util.UUID;

public interface DurableTaskRepository extends JpaRepository<DurableTask, UUID> {
    Optional<DurableTask> findByTenantIdAndId(String tenantId, UUID id);

    Optional<DurableTask> findByTenantIdAndAgentWorkloadIdAndTaskRef(String tenantId, UUID workloadId, String taskRef);

    /** Serializes resume, callback and end of one task. */
    @Query(value = "SELECT * FROM durable_tasks WHERE id = :id AND tenant_id = :tenant FOR UPDATE", nativeQuery = true)
    Optional<DurableTask> lock(@Param("id") UUID id, @Param("tenant") String tenantId);
}
