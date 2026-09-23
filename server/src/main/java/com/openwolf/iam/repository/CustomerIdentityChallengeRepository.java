package com.openwolf.iam.repository;

import com.openwolf.iam.entity.CustomerIdentityChallenge;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;
import java.util.List;
import java.util.UUID;

public interface CustomerIdentityChallengeRepository extends JpaRepository<CustomerIdentityChallenge, UUID> {
    Optional<CustomerIdentityChallenge> findByTenantIdAndTypeAndTokenHashAndUsedAtIsNull(
            String tenantId, CustomerIdentityChallenge.Type type, String tokenHash);
    List<CustomerIdentityChallenge> findByTenantIdAndCustomerIdAndTypeAndUsedAtIsNull(
            String tenantId, UUID customerId, CustomerIdentityChallenge.Type type);
}
