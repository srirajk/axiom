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
    @Query("select c from TenantApplicationClient c where c.clientId = :clientId")
    Optional<TenantApplicationClient> findByClientIdForUpdate(String clientId);
    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("select c from TenantApplicationClient c where c.id = :id")
    Optional<TenantApplicationClient> findByIdForUpdate(UUID id);
    boolean existsByExternalClientId(String externalClientId);
    List<TenantApplicationClient> findByExternalClientId(String externalClientId);
    @Query(value = "select c.* from tenant_application_clients c join tenant_applications a on a.id = c.application_id "
            + "where a.tenant_id = :tenantId and c.external_client_id is not null "
            + "and jsonb_exists(c.trusted_application_scopes, :applicationId)", nativeQuery = true)
    List<TenantApplicationClient> findTrustedForTenantApplication(String tenantId, String applicationId);
    boolean existsByApplicationIdAndExternalClientIdAndStatus(java.util.UUID applicationId, String externalClientId, TenantApplicationClient.Status status);
}
