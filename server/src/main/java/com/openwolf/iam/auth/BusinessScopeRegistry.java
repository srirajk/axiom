package com.openwolf.iam.auth;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.util.Arrays;
import java.util.Set;
import java.util.TreeSet;
import java.util.regex.Pattern;

/** Deployment-owned vocabulary of business scopes eligible for tenant client registration. */
@Component
public final class BusinessScopeRegistry {
    private static final Pattern SYNTAX = Pattern.compile("[a-z][a-z0-9-]*(?:[.:][a-z][a-z0-9-]*)+");
    private final Set<String> approved;

    public BusinessScopeRegistry(@Value("${iam.oauth2.approved-business-scopes:}") String configured) {
        TreeSet<String> values = new TreeSet<>();
        Arrays.stream(configured.split(",")).map(String::trim).filter(value -> !value.isBlank()).forEach(value -> {
            if (value.startsWith("axiom.") || !SYNTAX.matcher(value).matches()) {
                throw new IllegalStateException("invalid approved business scope configuration");
            }
            values.add(value);
        });
        this.approved = Set.copyOf(values);
    }

    /** Deployment-configured (Helm/environment) scopes only: approved in every tenant. */
    public boolean isApproved(String scope) { return approved.contains(scope); }
    /** The deployment-configured scopes (published in discovery; never a tenant's private catalog). */
    public Set<String> approvedScopes() { return approved; }
    public boolean isConfigured(String scope) { return approved.contains(scope); }

    /**
     * Approved for this tenant: a deployment-configured scope, or a name registered in the tenant's own catalog. Read
     * live from the database, so a registration is usable at once; an unknown name is denied. Approval is vocabulary
     * only and grants no authority.
     */
    public boolean isApproved(String tenantId, String scope) {
        if (scope == null) return false;
        if (approved.contains(scope)) return true;
        return tenantId != null && catalog != null && catalog.contains(tenantId, scope);
    }

    private com.openwolf.iam.scopes.TenantBusinessScopeCatalog catalog;

    @org.springframework.beans.factory.annotation.Autowired(required = false)
    void setCatalog(@org.springframework.context.annotation.Lazy com.openwolf.iam.scopes.TenantBusinessScopeCatalog catalog) {
        this.catalog = catalog;
    }

    private static final int MAX_CUSTOM_LENGTH = 128;
    /** First name segments reserved for the platform and for protocol vocabularies. */
    private static final Set<String> RESERVED_FIRST_SEGMENTS = Set.of(
            "axiom", "urn", "openid", "oidc", "oauth", "offline_access", "profile", "email", "roles", "phone", "address");

    /**
     * A tenant-registrable custom name: normalized syntax (lowercase segments joined by '.' or ':'), at most 128
     * characters, and a first segment that is not reserved for the platform (axiom) or a protocol vocabulary.
     */
    public static boolean isValidCustomName(String scope) {
        if (scope == null || scope.isEmpty() || scope.length() > MAX_CUSTOM_LENGTH || !SYNTAX.matcher(scope).matches()) {
            return false;
        }
        String first = scope.split("[.:]", 2)[0];
        return !RESERVED_FIRST_SEGMENTS.contains(first);
    }
}
