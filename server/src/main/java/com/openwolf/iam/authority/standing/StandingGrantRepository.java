package com.openwolf.iam.authority.standing;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

public interface StandingGrantRepository extends JpaRepository<StandingGrant, UUID> {
    Optional<StandingGrant> findByTenantIdAndId(String tenantId, UUID id);

    List<StandingGrant> findByTenantIdAndOwnerPrincipalIdOrderByCreatedAtDesc(String tenantId, String owner);

    List<StandingGrant> findByTenantIdOrderByCreatedAtDesc(String tenantId);

    /** Row lock: renewals and revocations of one grant are serialized, so a handle rotates exactly once. */
    @Query(value = "SELECT * FROM standing_grants WHERE id = :id FOR UPDATE", nativeQuery = true)
    Optional<StandingGrant> lock(@Param("id") UUID id);
}
