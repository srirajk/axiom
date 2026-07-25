package com.openwolf.iam.repository;

import com.openwolf.iam.entity.IamSession;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import jakarta.persistence.LockModeType;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

public interface IamSessionRepository extends JpaRepository<IamSession, UUID> {
    Optional<IamSession> findByIdAndTenantId(UUID id, String tenantId);

    @Query("""
            select s from IamSession s
            where s.tenantId = :tenantId
              and (:principalId is null or s.principalId = :principalId)
              and (:clientId is null or s.clientId = :clientId)
              and (:status is null or s.status = :status)
            order by s.lastSeenAt desc
            """)
    Page<IamSession> search(@Param("tenantId") String tenantId, @Param("principalId") String principalId,
                            @Param("clientId") String clientId, @Param("status") IamSession.Status status,
                            Pageable pageable);

    @Modifying
    @Query("update IamSession s set s.lastSeenAt = :seenAt where s.id = :id and s.tenantId = :tenantId and s.status = :activeStatus")
    int touch(@Param("id") UUID id, @Param("tenantId") String tenantId, @Param("seenAt") Instant seenAt,
              @Param("activeStatus") IamSession.Status activeStatus);

    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("select s from IamSession s where s.tenantId = :tenantId and s.recoveryMarked = true "
            + "and s.status = :active and (s.recoveryOperatorA = :operatorId or s.recoveryOperatorB = :operatorId)")
    java.util.List<IamSession> findActiveRecoverySessionsForOperatorForUpdate(
            @Param("tenantId") String tenantId, @Param("operatorId") UUID operatorId,
            @Param("active") IamSession.Status active);
}
