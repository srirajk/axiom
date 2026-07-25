package com.openwolf.iam.tenancy;

/**
 * A staging/verification step of a tenant provision (or deprovision) failed (Axiom B4). Throwing
 * this leaves the operation ledger row in a non-{@code ACTIVE} state and the tenant ABSENT from the
 * active directory — a half-provisioned tenant is fully unusable. A retry with the same idempotency
 * key resumes and idempotently reconciles.
 */
public class ProvisioningException extends RuntimeException {

    public ProvisioningException(String message) {
        super(message);
    }

    public ProvisioningException(String message, Throwable cause) {
        super(message, cause);
    }
}
