package com.openwolf.iam.scopes;

import com.openwolf.iam.auth.BusinessScopeRegistry;
import com.openwolf.iam.auth.ExecutionTenant;
import com.openwolf.iam.exception.EntityNotFoundException;
import com.openwolf.iam.exception.ResourceConflictException;
import com.openwolf.iam.service.AuditService;
import com.openwolf.iam.tenancy.ActiveTenantDirectory;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;

/**
 * Tenant administration of approved custom business-scope names. Registration is vocabulary administration only: it
 * makes the name eligible wherever this tenant validates business scopes (client registration, exchange routes, consent
 * purposes, delegation and grant scopes, issuance-time entitlement narrowing). It grants no user, workload, client,
 * route, consent or receiver authority. Create and list only: deactivation semantics are documented, not implemented.
 */
@Service
public class TenantBusinessScopeService {
    public static final String AUDIT_ACTION = "REGISTER_BUSINESS_SCOPE";
    private static final int MAX_DESCRIPTION = 256;

    public record ScopeResponse(UUID id, String tenantId, String scope, String description, String createdBy,
                                Instant createdAt) {}

    public record CatalogResponse(String tenantId, List<String> configured, List<ScopeResponse> registered) {}

    public record Registration(ScopeResponse scope, boolean created) {}

    private final TenantBusinessScopeCatalog catalog;
    private final BusinessScopeRegistry registry;
    private final ExecutionTenant executionTenant;
    private final ActiveTenantDirectory activeTenants;
    private final AuditService audit;
    private final TransactionTemplate transactions;

    public TenantBusinessScopeService(TenantBusinessScopeCatalog catalog, BusinessScopeRegistry registry,
                                      ExecutionTenant executionTenant, ActiveTenantDirectory activeTenants,
                                      AuditService audit, PlatformTransactionManager transactionManager) {
        this.catalog = catalog;
        this.registry = registry;
        this.executionTenant = executionTenant;
        this.activeTenants = activeTenants;
        this.audit = audit;
        this.transactions = new TransactionTemplate(transactionManager);
    }

    public Registration register(String tenantId, String rawScope, String rawDescription, String correlationId) {
        String actor = audit.currentActor();
        requireTenantAdmin(tenantId, actor, rawScope, correlationId);
        String scope = rawScope == null ? null : rawScope.strip();
        if (!BusinessScopeRegistry.isValidCustomName(scope)) {
            record(tenantId, actor, rawScope, "REJECTED_INVALID_OR_RESERVED", correlationId);
            throw new IllegalArgumentException("scope must be lowercase segments joined by '.' or ':', at most 128 "
                    + "characters, and must not use a reserved platform or protocol name");
        }
        String description = rawDescription == null || rawDescription.isBlank() ? null : rawDescription.strip();
        if (description != null && description.length() > MAX_DESCRIPTION) {
            record(tenantId, actor, scope, "REJECTED_INVALID_DESCRIPTION", correlationId);
            throw new IllegalArgumentException("description must be at most 256 characters");
        }
        if (registry.isConfigured(scope)) {
            record(tenantId, actor, scope, "REJECTED_CONFIGURED_BY_DEPLOYMENT", correlationId);
            throw new ResourceConflictException("scope is already approved by the deployment configuration");
        }
        Registration result = transactions.execute(status -> {
            boolean inserted = catalog.insertIfAbsent(tenantId, scope, description, actor);
            TenantBusinessScopeCatalog.Entry entry = catalog.find(tenantId, scope)
                    .orElseThrow(() -> new IllegalStateException("registered scope is not readable"));
            if (inserted) {
                record(tenantId, actor, scope, "CREATED", correlationId);
                return new Registration(response(entry), true);
            }
            if (description == null || Objects.equals(description, entry.description())) {
                record(tenantId, actor, scope, "ALREADY_REGISTERED", correlationId);
                return new Registration(response(entry), false);
            }
            return null;
        });
        if (result == null) {
            record(tenantId, actor, scope, "REJECTED_CONFLICT", correlationId);
            throw new ResourceConflictException("scope is already registered with a different description");
        }
        return result;
    }

    public CatalogResponse list(String tenantId) {
        requireTenantAdmin(tenantId, audit.currentActor(), null, null);
        return new CatalogResponse(tenantId, registry.approvedScopes().stream().sorted().toList(),
                catalog.list(tenantId).stream().map(TenantBusinessScopeService::response).toList());
    }

    /** Same boundary as the other tenant administration APIs: the caller's own tenant, or a platform administrator. */
    private void requireTenantAdmin(String tenantId, String actor, String scope, String correlationId) {
        String callerTenant = executionTenant.require();
        boolean own = tenantId.equals(callerTenant);
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        boolean platformAdmin = authentication != null && authentication.getAuthorities().stream()
                .anyMatch(authority -> "ROLE_platform_admin".equals(authority.getAuthority()));
        if ((!own && !platformAdmin) || !activeTenants.isActive(tenantId)) {
            if (scope != null) record(callerTenant, actor, scope, "REJECTED_TENANT_BOUNDARY", correlationId);
            throw EntityNotFoundException.forId("Tenant business-scope catalog", tenantId);
        }
    }

    private void record(String tenantId, String actor, String scope, String outcome, String correlationId) {
        Map<String, Object> fact = new LinkedHashMap<>();
        fact.put("tenantId", tenantId);
        String shown = scope == null ? null : scope.length() > 160 ? scope.substring(0, 160) : scope;
        fact.put("scope", shown);
        fact.put("outcome", outcome);
        fact.put("actor", actor);
        audit.logRequired(tenantId, actor, AUDIT_ACTION, "business_scope", shown == null ? "-" : shown,
                null, fact, correlationId);
    }

    private static ScopeResponse response(TenantBusinessScopeCatalog.Entry entry) {
        return new ScopeResponse(entry.id(), entry.tenantId(), entry.scope(), entry.description(), entry.createdBy(),
                entry.createdAt());
    }
}
