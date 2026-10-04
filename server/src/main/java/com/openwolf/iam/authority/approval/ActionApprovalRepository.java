package com.openwolf.iam.authority.approval;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

public interface ActionApprovalRepository extends JpaRepository<ActionApproval, UUID> {
    Optional<ActionApproval> findByTenantIdAndId(String tenantId, UUID id);

    @Query(value = "SELECT * FROM action_approvals WHERE id = :id AND tenant_id = :tenant FOR UPDATE", nativeQuery = true)
    Optional<ActionApproval> lock(@Param("id") UUID id, @Param("tenant") String tenantId);

    /**
     * Phase 3.8 single-use consumption: one conditional statement. Of any number of concurrent redemptions exactly
     * one changes the row; a wrong digest, an expired deadline or any status other than CONFIRMED changes nothing.
     */
    @Modifying(flushAutomatically = true)
    @Query(value = "UPDATE action_approvals SET status = 'CONSUMED', version = version + 1, consumed_at = :now, "
            + "consumed_by_client = :client WHERE id = :id AND tenant_id = :tenant AND status = 'CONFIRMED' "
            + "AND deadline > :now AND action_digest = :digest", nativeQuery = true)
    int consume(@Param("id") UUID id, @Param("tenant") String tenantId, @Param("digest") String digest,
                @Param("client") String clientId, @Param("now") Instant now);
}
