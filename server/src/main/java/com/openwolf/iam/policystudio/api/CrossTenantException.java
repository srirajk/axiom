package com.openwolf.iam.policystudio.api;

/** A request body named a tenant other than the principal's own tenant scope — rejected (403). */
class CrossTenantException extends RuntimeException {
    CrossTenantException(String message) {
        super(message);
    }
}
