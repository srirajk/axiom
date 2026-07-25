package com.openwolf.iam.tenancy;

import org.springframework.stereotype.Component;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.transaction.annotation.Transactional;

/**
 * Transactional boundaries for the provisioning saga. No method in the orchestration layer keeps a
 * database transaction open across Cerbos, Redis, audit, or other external work.
 */
@Component
public class ProvisioningLedger {

    private final ProvisioningOperationRepository operations;
    private final ActiveTenantDirectory directory;
    private final TenantLifecycleLockStore lifecycleLocks;
    private final ProvisioningLedgerTransactions transactions;

    @Autowired
    public ProvisioningLedger(ProvisioningOperationRepository operations,
                              ActiveTenantDirectory directory,
                              TenantLifecycleLockStore lifecycleLocks,
                              ProvisioningLedgerTransactions transactions) {
        this.operations = operations;
        this.directory = directory;
        this.lifecycleLocks = lifecycleLocks;
        this.transactions = transactions;
    }

    /** Direct constructor retained for unit tests without Spring transaction proxies. */
    public ProvisioningLedger(ProvisioningOperationRepository operations,
                              ActiveTenantDirectory directory,
                              TenantLifecycleLockStore lifecycleLocks) {
        this(operations, directory, lifecycleLocks, new ProvisioningLedgerTransactions(operations));
    }

    public ProvisioningLease startOrResumeProvision(String key, ProvisioningRequest request) {
        TenantLifecycleLockStore.Lease lease = lifecycleLocks.acquire(request.tenantId());
        try {
            ProvisioningOperation operation = transactions.startProvision(key, request);
            return new ProvisioningLease(operation, lease);
        } catch (RuntimeException e) {
            lease.close();
            throw e;
        }
    }

    public ProvisioningLease startOrResumeDeprovision(String key, String tenantId) {
        TenantLifecycleLockStore.Lease lease = lifecycleLocks.acquire(tenantId);
        try {
            ProvisioningOperation operation = transactions.startDeprovision(key, tenantId);
            return new ProvisioningLease(operation, lease);
        } catch (RuntimeException e) {
            lease.close();
            throw e;
        }
    }

    @Transactional
    public void saveProgress(ProvisioningOperation operation) {
        operations.save(operation);
    }

    /** Directory CAS and ACTIVE ledger update share one transaction and rollback together. */
    @Transactional
    public long activate(ProvisioningOperation operation, String tenantId,
                         String expectedPolicyVersion, String policyVersion) {
        long directoryVersion;
        String current = directory.find(tenantId).orElse(null);
        if (current == null) {
            directoryVersion = directory.compareAndActivate(tenantId, expectedPolicyVersion, policyVersion);
        } else if (current.equals(policyVersion)) {
            directoryVersion = directory.version();
        } else {
            throw new ProvisioningException("tenant '" + tenantId + "' is already active at policy version '"
                    + current + "', not requested bootstrap '" + policyVersion + "'");
        }
        operation.setStatus(ProvisioningOperation.Status.ACTIVE);
        operation.setLastError(null);
        operations.save(operation);
        return directoryVersion;
    }

    /** Deactivation is committed before non-audit external cleanup begins. */
    @Transactional
    public long deactivate(String tenantId) {
        return directory.deactivate(tenantId);
    }

    @Transactional
    public void markFailed(ProvisioningOperation operation, RuntimeException failure) {
        operation.setStatus(ProvisioningOperation.Status.FAILED);
        operation.setLastError(failure.toString());
        operations.save(operation);
    }

    @Transactional
    public void markDeactivated(ProvisioningOperation operation) {
        operation.setStatus(ProvisioningOperation.Status.DEACTIVATED);
        operations.save(operation);
    }

    public void release(ProvisioningLease provisioningLease) {
        provisioningLease.lease().close();
    }

    public record ProvisioningLease(ProvisioningOperation operation,
                                    TenantLifecycleLockStore.Lease lease) {
        public void assertOwned() { lease.assertOwned(); }
    }
}
