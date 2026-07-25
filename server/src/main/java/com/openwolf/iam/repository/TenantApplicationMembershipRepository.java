package com.openwolf.iam.repository;

import com.openwolf.iam.entity.TenantApplicationMembership;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

public interface TenantApplicationMembershipRepository extends JpaRepository<TenantApplicationMembership, UUID> {
    Optional<TenantApplicationMembership> findByApplicationIdAndPrincipalId(UUID applicationId, String principalId);
    Optional<TenantApplicationMembership> findByIdAndApplicationId(UUID id, UUID applicationId);
    List<TenantApplicationMembership> findByApplicationIdOrderByPrincipalId(UUID applicationId);
}
