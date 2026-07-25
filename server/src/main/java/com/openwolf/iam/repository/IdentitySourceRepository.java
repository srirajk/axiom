package com.openwolf.iam.repository;

import com.openwolf.iam.entity.IdentitySource;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Query;
import jakarta.persistence.LockModeType;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

public interface IdentitySourceRepository extends JpaRepository<IdentitySource, UUID> {
    List<IdentitySource> findByTenantIdOrderByDisplayName(String tenantId);
    Optional<IdentitySource> findByIdAndTenantId(UUID id, String tenantId);
    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("select s from IdentitySource s where s.id = :id and s.tenantId = :tenantId")
    Optional<IdentitySource> findByIdAndTenantIdForUpdate(UUID id, String tenantId);
    boolean existsByTenantIdAndIssuer(String tenantId, String issuer);
}
