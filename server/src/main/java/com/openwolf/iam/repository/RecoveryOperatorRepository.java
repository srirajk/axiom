package com.openwolf.iam.repository;

import com.openwolf.iam.entity.RecoveryOperator;
import jakarta.persistence.LockModeType;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

public interface RecoveryOperatorRepository extends JpaRepository<RecoveryOperator, UUID> {
    List<RecoveryOperator> findByTenantIdOrderByCreatedAt(String tenantId);
    Optional<RecoveryOperator> findByTenantIdAndPrincipalId(String tenantId, String principalId);
    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("select r from RecoveryOperator r where r.tenantId = :tenantId and r.principalId = :principalId")
    Optional<RecoveryOperator> findByTenantIdAndPrincipalIdForUpdate(@Param("tenantId") String tenantId,
                                                                       @Param("principalId") String principalId);
    Optional<RecoveryOperator> findByIdAndTenantId(UUID id, String tenantId);
    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("select r from RecoveryOperator r where r.id = :id and r.tenantId = :tenantId")
    Optional<RecoveryOperator> findByIdAndTenantIdForUpdate(@Param("id") UUID id, @Param("tenantId") String tenantId);
}
