package com.openwolf.iam.repository;

import com.openwolf.iam.entity.CustomerIdentityChallenge;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.time.Instant;

import java.util.Optional;
import java.util.List;
import java.util.UUID;

public interface CustomerIdentityChallengeRepository extends JpaRepository<CustomerIdentityChallenge, UUID> {
    Optional<CustomerIdentityChallenge> findByTenantIdAndTypeAndTokenHashAndUsedAtIsNull(
            String tenantId, CustomerIdentityChallenge.Type type, String tokenHash);
    List<CustomerIdentityChallenge> findByTenantIdAndCustomerIdAndTypeAndUsedAtIsNull(
            String tenantId, UUID customerId, CustomerIdentityChallenge.Type type);

    /**
     * One-use consumption as a single conditional statement (Phase 3.1): of any number of concurrent attempts with the
     * same code, exactly one changes the row; expired or already-used challenges never change.
     */
    @Modifying(flushAutomatically = true)
    @Query(value = "UPDATE customer_identity_challenges SET used_at = :now WHERE id = :id AND used_at IS NULL "
            + "AND expires_at > :now", nativeQuery = true)
    int consume(@Param("id") UUID id, @Param("now") Instant now);

    @Query(value = "SELECT count(*) FROM customer_identity_challenges WHERE tenant_id = :tenant "
            + "AND customer_id = :customer AND challenge_type = :type AND created_at > :since", nativeQuery = true)
    long countIssuedSince(@Param("tenant") String tenantId, @Param("customer") UUID customerId,
                          @Param("type") String type, @Param("since") Instant since);
}
