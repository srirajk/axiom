package com.openwolf.iam.repository;

import com.openwolf.iam.entity.TenantApplicationClient;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Query;
import jakarta.persistence.LockModeType;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

public interface TenantApplicationClientRepository extends JpaRepository<TenantApplicationClient, UUID> {
    List<TenantApplicationClient> findByApplicationIdOrderByClientId(UUID applicationId);
    Optional<TenantApplicationClient> findByIdAndApplicationId(UUID id, UUID applicationId);
    Optional<TenantApplicationClient> findByClientId(String clientId);
    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("select c from TenantApplicationClient c where c.id = :id")
    Optional<TenantApplicationClient> findByIdForUpdate(UUID id);
}
