package com.openwolf.iam.repository;

import com.openwolf.iam.entity.TenantApplicationRoleAssignment;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

public interface TenantApplicationRoleAssignmentRepository extends JpaRepository<TenantApplicationRoleAssignment, UUID> {
    Optional<TenantApplicationRoleAssignment> findByMembershipIdAndApplicationRoleIdAndRevokedAtIsNull(UUID membershipId, UUID roleId);
    List<TenantApplicationRoleAssignment> findByMembershipIdAndRevokedAtIsNull(UUID membershipId);
}
