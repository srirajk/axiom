package com.openwolf.iam.repository;

import com.openwolf.iam.entity.TenantApplicationRole;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

public interface TenantApplicationRoleRepository extends JpaRepository<TenantApplicationRole, UUID> {
    boolean existsByApplicationIdAndRoleKey(UUID applicationId, String roleKey);
    Optional<TenantApplicationRole> findByIdAndApplicationId(UUID id, UUID applicationId);
    List<TenantApplicationRole> findByApplicationIdOrderByRoleKey(UUID applicationId);
}
