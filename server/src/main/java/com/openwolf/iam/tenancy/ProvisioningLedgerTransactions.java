package com.openwolf.iam.tenancy;

import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

/** Persistence-only boundaries used after the tenant lifecycle session fence is acquired. */
@Component
public class ProvisioningLedgerTransactions {

    private final ProvisioningOperationRepository operations;

    public ProvisioningLedgerTransactions(ProvisioningOperationRepository operations) {
        this.operations = operations;
    }

    @Transactional
    public ProvisioningOperation startProvision(String key, ProvisioningRequest request) {
        operations.lockIdempotencyKey(key);
        return operations.findByIdempotencyKey(key)
                .map(existing -> {
                    if (existing.getKind() != ProvisioningOperation.Kind.PROVISION) {
                        throw new ProvisioningException("idempotency key '" + key
                                + "' already used for a " + existing.getKind() + " operation");
                    }
                    if (!existing.getTenantId().equals(request.tenantId())) {
                        throw new ProvisioningException("idempotency key '" + key
                                + "' already bound to tenant '" + existing.getTenantId() + "'");
                    }
                    return existing;
                })
                .orElseGet(() -> operations.save(new ProvisioningOperation(
                        key, request.tenantId(), request.name(), request.slug(),
                        ProvisioningOperation.Kind.PROVISION)));
    }

    @Transactional
    public ProvisioningOperation startDeprovision(String key, String tenantId) {
        operations.lockIdempotencyKey(key);
        return operations.findByIdempotencyKey(key)
                .map(existing -> {
                    if (existing.getKind() != ProvisioningOperation.Kind.DEPROVISION
                            || !existing.getTenantId().equals(tenantId)) {
                        throw new ProvisioningException("idempotency key '" + key
                                + "' is bound to another lifecycle operation");
                    }
                    return existing;
                })
                .orElseGet(() -> operations.save(new ProvisioningOperation(
                        key, tenantId, tenantId, tenantId, ProvisioningOperation.Kind.DEPROVISION)));
    }
}
