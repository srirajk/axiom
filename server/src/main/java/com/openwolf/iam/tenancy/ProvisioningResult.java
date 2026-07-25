package com.openwolf.iam.tenancy;

import java.util.Set;
import java.util.UUID;

/**
 * The outcome of a provisioning run (Axiom B4). On {@code ACTIVE} the tenant is fully visible; any
 * other status means the tenant is absent from the active directory and fully unusable until a retry
 * with the same idempotency key reconciles it.
 */
public record ProvisioningResult(
        UUID operationId,
        String tenantId,
        ProvisioningOperation.Status status,
        String policyVersion,
        long directoryVersion,
        Set<ProvisioningOperation.Artifact> stagedArtifacts) {

    public boolean isActive() {
        return status == ProvisioningOperation.Status.ACTIVE;
    }

    static ProvisioningResult of(ProvisioningOperation op, long directoryVersion) {
        return new ProvisioningResult(op.getId(), op.getTenantId(), op.getStatus(),
                op.getPolicyVersion(), directoryVersion, op.stagedArtifacts());
    }
}
