package com.openwolf.iam.bootstrap;

import com.openwolf.iam.entity.Principal;
import com.openwolf.iam.entity.Role;
import com.openwolf.iam.entity.Tenant;
import com.openwolf.iam.repository.AuditLogRepository;
import com.openwolf.iam.repository.PrincipalRepository;
import com.openwolf.iam.repository.RoleRepository;
import com.openwolf.iam.repository.TenantRepository;
import com.openwolf.iam.service.AuditService;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * The short, identity-only transaction for first-tenant bootstrap. External policy and Redis
 * provisioning is deliberately performed by the runner after this method commits.
 */
@Service
public class FirstTenantIdentityBootstrapService {

    private static final ObjectMapper JSON = new ObjectMapper();

    private final TenantRepository tenants;
    private final RoleRepository roles;
    private final PrincipalRepository principals;
    private final AuditLogRepository audits;
    private final PasswordEncoder passwords;
    private final AuditService audit;

    public FirstTenantIdentityBootstrapService(
            TenantRepository tenants,
            RoleRepository roles,
            PrincipalRepository principals,
            AuditLogRepository audits,
            PasswordEncoder passwords,
            AuditService audit) {
        this.tenants = tenants;
        this.roles = roles;
        this.principals = principals;
        this.audits = audits;
        this.passwords = passwords;
        this.audit = audit;
    }

    @Transactional
    public void ensureExact(BootstrapIdentity identity) {
        long tenantCount = tenants.count();
        long roleCount = roles.count();
        long principalCount = principals.count();
        if (tenantCount == 0 && roleCount == 0 && principalCount == 0) {
            Tenant tenant = tenants.save(new Tenant(identity.tenantId(), identity.tenantName(),
                    identity.tenantSlug(), "[]"));
            Role platformAdmin = roles.save(new Role(identity.tenantId(), "platform_admin", "[\"*\"]",
                    "Initial platform administrator"));
            Principal admin = new Principal(identity.adminId(), identity.tenantId(), identity.adminUsername(),
                    identity.adminEmail(), passwords.encode(identity.adminPassword()), true,
                    "{\"admin_domains\":[]}");
            admin.assignRole(platformAdmin);
            principals.save(admin);
            audit.logRequired(identity.tenantId(), identity.adminId(), "AXIOM_FIRST_TENANT_BOOTSTRAPPED",
                    "tenant", tenant.getId(), null, tenant, identity.correlationId());
            return;
        }
        // A replay after the supported directory seed is expected to find additional principals
        // and roles. The deployment boundary is the single exact tenant; the bootstrap-owned
        // platform administrator is verified below. Extra identities in that same tenant are not
        // partial bootstrap state and must not make a normal container restart impossible.
        if (tenantCount != 1 || roleCount < 1 || principalCount < 1) {
            throw new IllegalStateException("first bootstrap refuses partial or unrelated Axiom identity state");
        }

        Tenant tenant = tenants.findById(identity.tenantId())
                .orElseThrow(() -> new IllegalStateException("completed bootstrap tenant does not match requested tenant-id"));
        Role platformAdmin = roles.findByNameAndTenantId("platform_admin", identity.tenantId())
                .orElseThrow(() -> new IllegalStateException("completed bootstrap platform_admin role is absent"));
        Principal admin = principals.findById(identity.adminId())
                .orElseThrow(() -> new IllegalStateException("completed bootstrap administrator does not match requested admin-id"));
        boolean exactTenant = identity.tenantName().equals(tenant.getName())
                && identity.tenantSlug().equals(tenant.getSlug())
                && "[]".equals(tenant.getClassificationSchema());
        boolean exactRole = identity.tenantId().equals(platformAdmin.getTenantId())
                && "[\"*\"]".equals(platformAdmin.getPermissions())
                && "Initial platform administrator".equals(platformAdmin.getDescription());
        boolean exactAdmin = identity.tenantId().equals(admin.getTenantId())
                && identity.adminUsername().equals(admin.getUsername())
                && identity.adminEmail().equals(admin.getEmail())
                && admin.isActive()
                && jsonEquivalent("{\"admin_domains\":[]}", admin.getAttributes())
                && passwords.matches(identity.adminPassword(), admin.getPasswordHash())
                && admin.getRoles().size() == 1
                && admin.getRoles().contains(platformAdmin);
        long auditCount = audits.countByTenantIdAndActionAndResourceTypeAndResourceId(
                identity.tenantId(), "AXIOM_FIRST_TENANT_BOOTSTRAPPED", "tenant", identity.tenantId());
        if (!exactTenant || !exactRole || !exactAdmin || auditCount != 1) {
            throw new IllegalStateException("completed bootstrap state drifted; refuse replay until it is reconciled deliberately");
        }
    }

    private static boolean jsonEquivalent(String expected, String actual) {
        try {
            JsonNode expectedNode = JSON.readTree(expected);
            JsonNode actualNode = JSON.readTree(actual);
            return expectedNode != null && expectedNode.equals(actualNode);
        } catch (Exception ignored) {
            return false;
        }
    }

    public record BootstrapIdentity(
            String tenantId,
            String tenantName,
            String tenantSlug,
            String adminId,
            String adminUsername,
            String adminEmail,
            String adminPassword) {
        public BootstrapIdentity {
            require(tenantId, "tenant-id");
            require(tenantName, "tenant-name");
            require(tenantSlug, "tenant-slug");
            require(adminId, "admin-id");
            require(adminUsername, "admin-username");
            require(adminEmail, "admin-email");
            require(adminPassword, "admin-password");
        }

        String correlationId() {
            return "axiom-first-bootstrap:" + tenantId + ":" + adminId;
        }

        private static void require(String value, String name) {
            if (value == null || value.isBlank()) {
                throw new IllegalStateException("axiom.bootstrap." + name + " is required");
            }
        }
    }
}
