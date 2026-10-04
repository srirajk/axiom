package com.openwolf.iam.dto;

/**
 * The service secret is populated only when Axiom generated it (create/rotation without an operator-supplied secret)
 * and is never persisted in this DTO. It is null for public clients and for operator-supplied secrets.
 */
public record CreatedTenantApplicationClientResponse(TenantApplicationClientResponse client, String serviceSecret) {
    @Override
    public String toString() {
        return "CreatedTenantApplicationClientResponse[client=" + client + ", serviceSecret="
                + (serviceSecret == null ? "absent" : "[REDACTED]") + "]";
    }
}
