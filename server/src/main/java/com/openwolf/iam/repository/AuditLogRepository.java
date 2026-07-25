package com.openwolf.iam.repository;

import com.openwolf.iam.entity.AuditLog;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.UUID;

@Repository
public interface AuditLogRepository extends JpaRepository<AuditLog, UUID> {

    Page<AuditLog> findByTenantIdOrderByOccurredAtDesc(String tenantId, Pageable pageable);

    List<AuditLog> findByTenantIdOrderByOccurredAtDesc(String tenantId);

    List<AuditLog> findByActorIdOrderByOccurredAtDesc(String actorId);

    boolean existsByTenantIdAndActionAndResourceTypeAndResourceIdAndCorrelationId(
            String tenantId, String action, String resourceType, String resourceId, String correlationId);

    long countByTenantIdAndActionAndResourceTypeAndResourceId(
            String tenantId, String action, String resourceType, String resourceId);
}
