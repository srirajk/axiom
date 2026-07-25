package com.openwolf.iam.repository;

import com.openwolf.iam.entity.TenantApplication;
import org.springframework.data.jpa.repository.JpaRepository;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

public interface TenantApplicationRepository extends JpaRepository<TenantApplication, UUID> {
    List<TenantApplication> findByTenantIdOrderByApplicationKey(String tenantId);
    Optional<TenantApplication> findByIdAndTenantId(UUID id, String tenantId);
    boolean existsByTenantIdAndApplicationKey(String tenantId, String applicationKey);
}
