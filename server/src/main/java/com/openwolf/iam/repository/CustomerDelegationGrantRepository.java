package com.openwolf.iam.repository;

import com.openwolf.iam.entity.CustomerDelegationGrant;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

public interface CustomerDelegationGrantRepository extends JpaRepository<CustomerDelegationGrant, UUID> {
    Optional<CustomerDelegationGrant> findByTenantIdAndCustomerIdAndId(
            String tenantId, UUID customerId, UUID id);
    List<CustomerDelegationGrant> findByTenantIdAndCustomerIdOrderByCreatedAtDesc(
            String tenantId, UUID customerId);
    List<CustomerDelegationGrant> findByTenantIdAndCustomerIdAndStatus(
            String tenantId, UUID customerId, CustomerDelegationGrant.Status status);
    List<CustomerDelegationGrant> findByTenantIdAndAgentWorkloadIdAndStatus(
            String tenantId, UUID workloadId, CustomerDelegationGrant.Status status);
    List<CustomerDelegationGrant> findByTenantIdOrderByCreatedAtDesc(String tenantId);
}
