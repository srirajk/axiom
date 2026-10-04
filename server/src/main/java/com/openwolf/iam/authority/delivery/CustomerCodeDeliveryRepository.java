package com.openwolf.iam.authority.delivery;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

public interface CustomerCodeDeliveryRepository extends JpaRepository<CustomerCodeDelivery, UUID> {

    Optional<CustomerCodeDelivery> findByChallengeId(UUID challengeId);

    /**
     * Claims a due delivery for one attempt by setting a short lease; only one worker can hold it. Returns 1 when
     * claimed. A crashed worker's lease simply expires and the delivery becomes due again.
     */
    @Modifying
    @Query(value = "UPDATE customer_code_deliveries SET lease_until = :leaseUntil, attempts = attempts + 1, "
            + "updated_at = :now WHERE id = :id AND status = 'PENDING' AND next_attempt_at <= :now "
            + "AND (lease_until IS NULL OR lease_until < :now)", nativeQuery = true)
    int claim(@Param("id") UUID id, @Param("now") Instant now, @Param("leaseUntil") Instant leaseUntil);

    @Modifying
    @Query(value = "UPDATE customer_code_deliveries SET status = 'SENT', protected_code = NULL, lease_until = NULL, "
            + "sent_at = :now, updated_at = :now, provider = :provider, provider_message_ref = :ref, last_failure = NULL "
            + "WHERE id = :id AND status = 'PENDING'", nativeQuery = true)
    int markSent(@Param("id") UUID id, @Param("provider") String provider, @Param("ref") String ref,
                 @Param("now") Instant now);

    @Modifying
    @Query(value = "UPDATE customer_code_deliveries SET lease_until = NULL, next_attempt_at = :next, "
            + "last_failure = :failure, provider = :provider, updated_at = :now WHERE id = :id AND status = 'PENDING'",
            nativeQuery = true)
    int markRetry(@Param("id") UUID id, @Param("next") Instant next, @Param("failure") String failure,
                  @Param("provider") String provider, @Param("now") Instant now);

    @Modifying
    @Query(value = "UPDATE customer_code_deliveries SET status = 'ABANDONED', protected_code = NULL, lease_until = NULL, "
            + "last_failure = :failure, updated_at = :now WHERE id = :id AND status = 'PENDING'", nativeQuery = true)
    int abandon(@Param("id") UUID id, @Param("failure") String failure, @Param("now") Instant now);

    /** Pending deliveries of earlier challenges are abandoned when a newer challenge of the same kind is issued. */
    @Modifying
    @Query(value = "UPDATE customer_code_deliveries SET status = 'ABANDONED', protected_code = NULL, lease_until = NULL, "
            + "last_failure = 'superseded', updated_at = :now WHERE tenant_id = :tenant AND customer_id = :customer "
            + "AND purpose = :purpose AND status = 'PENDING'", nativeQuery = true)
    int abandonPending(@Param("tenant") String tenantId, @Param("customer") UUID customerId,
                       @Param("purpose") String purpose, @Param("now") Instant now);

    @Query(value = "SELECT id FROM customer_code_deliveries WHERE status = 'PENDING' AND next_attempt_at <= :now "
            + "AND (lease_until IS NULL OR lease_until < :now) ORDER BY next_attempt_at LIMIT :limit", nativeQuery = true)
    List<UUID> due(@Param("now") Instant now, @Param("limit") int limit);
}
