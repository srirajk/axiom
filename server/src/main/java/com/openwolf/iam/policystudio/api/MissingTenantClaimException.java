package com.openwolf.iam.policystudio.api;

/** The authenticated principal carries no usable {@code tenant_id} claim — fail closed (403). */
class MissingTenantClaimException extends RuntimeException {
    MissingTenantClaimException(String message) {
        super(message);
    }
}
