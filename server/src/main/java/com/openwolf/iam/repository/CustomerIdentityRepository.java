package com.openwolf.iam.repository;

import com.openwolf.iam.entity.CustomerIdentity;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;
import java.util.List;
import java.util.UUID;

public interface CustomerIdentityRepository extends JpaRepository<CustomerIdentity, UUID> {
    Optional<CustomerIdentity> findByTenantIdAndId(String tenantId, UUID id);
    Optional<CustomerIdentity> findByTenantIdAndEmailIgnoreCase(String tenantId, String email);
    List<CustomerIdentity> findByTenantIdOrderByCreatedAtAsc(String tenantId);
}
