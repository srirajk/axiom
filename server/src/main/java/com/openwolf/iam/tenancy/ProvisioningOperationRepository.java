package com.openwolf.iam.tenancy;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

/**
 * The provisioning-operation ledger (Axiom B4). The idempotency key is unique, so a retry loads the
 * same row and resumes/reconciles instead of starting a conflicting second run.
 */
@Repository
public interface ProvisioningOperationRepository extends JpaRepository<ProvisioningOperation, UUID> {

    /**
     * Serialize same-key retries before the unique idempotency row is read or inserted. The lock key is namespaced:
     * the tenant lifecycle session lock uses {@code hashtextextended(tenantId)}, so an idempotency key equal to the
     * tenant id (a natural client choice) used to wait on the request's own session lock forever.
     */
    @Query(value = "SELECT pg_advisory_xact_lock(hashtextextended('provisioning-idempotency:' || :idempotencyKey, 0))",
            nativeQuery = true)
    void lockIdempotencyKey(String idempotencyKey);

    Optional<ProvisioningOperation> findByIdempotencyKey(String idempotencyKey);

    List<ProvisioningOperation> findByTenantIdOrderByCreatedAtDesc(String tenantId);
}
