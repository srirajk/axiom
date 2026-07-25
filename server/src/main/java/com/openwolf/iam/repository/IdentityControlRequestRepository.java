package com.openwolf.iam.repository;

import com.openwolf.iam.entity.IdentityControlRequest;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import jakarta.persistence.LockModeType;
import java.util.Optional;
import java.util.UUID;

public interface IdentityControlRequestRepository extends JpaRepository<IdentityControlRequest, UUID> {
    Optional<IdentityControlRequest> findForReadByIdAndTenantId(UUID id, String tenantId);

    @Lock(LockModeType.PESSIMISTIC_WRITE)
    Optional<IdentityControlRequest> findForUpdateByIdAndTenantId(UUID id, String tenantId);

    @Query("""
            select r from IdentityControlRequest r
            where r.tenantId = :tenantId
              and (:status is null or r.status = :status)
            order by r.createdAt desc
            """)
    Page<IdentityControlRequest> search(@Param("tenantId") String tenantId,
                                        @Param("status") IdentityControlRequest.Status status,
                                        Pageable pageable);
}
