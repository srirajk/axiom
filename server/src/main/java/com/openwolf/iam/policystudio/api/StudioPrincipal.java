package com.openwolf.iam.policystudio.api;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;

import java.util.Set;
import java.util.stream.Collectors;

/**
 * Resolves the acting principal and — critically — the tenant scope from the authenticated token's
 * {@code tenant_id} claim (Axiom A1/A2), <b>never</b> from a request field. Every studio controller
 * derives the tenant here, so a drafter/approver can only ever act inside their own tenant; a body
 * that names another tenant is rejected by comparing it to this value.
 *
 * <p>Mirrors {@code AuditService#currentTenant()} (the established IAM pattern for reading the claim
 * off the {@link Jwt} principal), but fails closed rather than falling back to a default tenant: a
 * missing/blank claim is a {@link MissingTenantClaimException} (403), never an implicit tenant.
 */
final class StudioPrincipal {

    private StudioPrincipal() {}

    /** The authenticated subject id (the SoD "actor"). */
    static String actor(Authentication authentication) {
        if (authentication == null || authentication.getName() == null || authentication.getName().isBlank()) {
            throw new MissingTenantClaimException("no authenticated principal");
        }
        return authentication.getName();
    }

    /** The tenant scope from the {@code tenant_id} claim — the only source of tenant, never a body field. */
    static String tenant(Authentication authentication) {
        if (authentication != null && authentication.getPrincipal() instanceof Jwt jwt) {
            String claim = jwt.getClaimAsString("tenant_id");
            if (claim != null && !claim.isBlank()) {
                return claim;
            }
        }
        throw new MissingTenantClaimException(
                "authenticated principal carries no 'tenant_id' claim — refusing to derive a tenant scope");
    }

    /** The principal's roles (Spring authorities with the {@code ROLE_} prefix stripped). */
    static Set<String> roles(Authentication authentication) {
        if (authentication == null) {
            return Set.of();
        }
        return authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .map(a -> a.startsWith("ROLE_") ? a.substring("ROLE_".length()) : a)
                .collect(Collectors.toSet());
    }

    /** Assert the body's tenant equals the principal's tenant scope — the cross-tenant guard. */
    static void assertSameTenant(String principalTenant, String bodyTenant) {
        if (bodyTenant == null || !bodyTenant.equals(principalTenant)) {
            throw new CrossTenantException(
                    "principal is scoped to tenant '" + principalTenant + "' and may not act on tenant '"
                            + bodyTenant + "'");
        }
    }
}
