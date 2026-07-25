package com.openwolf.iam.policystudio.lifecycle;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;
import org.springframework.data.repository.query.Param;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.transaction.annotation.Transactional;
import jakarta.persistence.LockModeType;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

/**
 * The durable promotion/rollback ledger (Axiom Story C5). The idempotency-key lookup is what makes a
 * retry idempotent: a lost-response retry finds the existing PROMOTED receipt and returns it rather than
 * driving a second CAS (C5.3).
 */
@Repository
public interface PromotionRepository extends JpaRepository<PromotionRecord, UUID> {

    /** Serialize first-use races for one promotion idempotency key in the ledger transaction. */
    @Transactional
    @Query(value = "SELECT pg_advisory_xact_lock(hashtextextended(:key, 2))", nativeQuery = true)
    void lockIdempotencyKey(@Param("key") String key);

    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("select p from PromotionRecord p where p.idempotencyKey = :key")
    Optional<PromotionRecord> findByIdempotencyKeyForUpdate(@Param("key") String key);

    @Modifying
    @Query("update PromotionRecord p set p.lastError = :error, p.status = :failed "
            + "where p.idempotencyKey = :key and p.status <> :promoted")
    int markFailedIfNotPromoted(@Param("key") String key, @Param("error") String error,
                                @Param("failed") PromotionRecord.Status failed,
                                @Param("promoted") PromotionRecord.Status promoted);

    Optional<PromotionRecord> findByIdempotencyKey(String idempotencyKey);

    List<PromotionRecord> findByTenantIdOrderByCreatedAtDesc(String tenantId);
}
