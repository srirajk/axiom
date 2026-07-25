package com.openwolf.iam.repository;

import com.openwolf.iam.entity.ScimProvisioningSource;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Query;
import jakarta.persistence.LockModeType;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

public interface ScimProvisioningSourceRepository extends JpaRepository<ScimProvisioningSource, UUID> {
    Optional<ScimProvisioningSource> findBySelector(String selector);
    Optional<ScimProvisioningSource> findByIdAndTenantId(UUID id, String tenantId);
    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("select s from ScimProvisioningSource s where s.id = :id and s.tenantId = :tenantId")
    Optional<ScimProvisioningSource> findByIdAndTenantIdForUpdate(UUID id, String tenantId);
    List<ScimProvisioningSource> findByTenantIdOrderByDisplayName(String tenantId);
    boolean existsByTenantIdAndDisplayName(String tenantId, String displayName);
}
