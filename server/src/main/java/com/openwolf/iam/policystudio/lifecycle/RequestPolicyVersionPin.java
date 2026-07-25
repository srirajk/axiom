package com.openwolf.iam.policystudio.lifecycle;

import com.openwolf.iam.tenancy.ActiveTenantDirectory;

import java.time.Instant;

/**
 * The active bundle id a request captures ONCE at its start (Axiom Story C5, mirroring the serving
 * {@code TenantExecutionContext.activePolicyVersion}). Every authorization check within the request reads
 * this immutable pin, never the live directory — so a promotion that advances the directory mid-request
 * cannot split one request across two policy versions (C5.5). The pin is a value: once captured it never
 * changes, regardless of what the directory does next.
 *
 * @param tenantId            the tenant the request runs under
 * @param activePolicyVersion the bundle id captured at request start ({@code null} ⇒ tenant not active)
 * @param capturedAt          when the capture happened
 */
public record RequestPolicyVersionPin(String tenantId, String activePolicyVersion, Instant capturedAt) {

    /** Capture the tenant's current active bundle id once, at request start. */
    public static RequestPolicyVersionPin capture(String tenantId, ActiveTenantDirectory directory) {
        return new RequestPolicyVersionPin(
                tenantId, directory.find(tenantId).orElse(null), Instant.now());
    }

    public boolean isActive() {
        return activePolicyVersion != null;
    }
}
