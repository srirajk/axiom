package com.openwolf.iam.bootstrap;

import com.openwolf.iam.policystudio.lifecycle.PolicyBundleRepository;
import com.openwolf.iam.tenancy.ProvisioningRequest;
import com.openwolf.iam.tenancy.ProvisioningResult;
import com.openwolf.iam.tenancy.TenantNamespaceAdapter;
import com.openwolf.iam.tenancy.TenantProvisioningService;
import com.openwolf.iam.tenancy.ActiveTenantDirectory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;

/**
 * One-shot, service-level bootstrap for an otherwise empty Axiom database. Identity is committed
 * first; the normal retryable tenant-provisioning saga then creates the active policy runtime and
 * Redis namespace. It is enabled only by the non-HTTP bootstrap command.
 */
@Component
@ConditionalOnProperty(prefix = "axiom.bootstrap", name = "enabled", havingValue = "true")
public class FirstTenantBootstrapRunner implements ApplicationRunner {

    private final FirstTenantIdentityBootstrapService identityBootstrap;
    private final TenantProvisioningService provisioning;
    private final ActiveTenantDirectory activeTenants;
    private final TenantNamespaceAdapter namespaces;
    private final PolicyBundleRepository policyBundles;

    @Value("${axiom.bootstrap.tenant-id:}") private String tenantId;
    @Value("${axiom.bootstrap.tenant-name:}") private String tenantName;
    @Value("${axiom.bootstrap.tenant-slug:}") private String tenantSlug;
    @Value("${axiom.bootstrap.admin-id:}") private String adminId;
    @Value("${axiom.bootstrap.admin-username:}") private String adminUsername;
    @Value("${axiom.bootstrap.admin-email:}") private String adminEmail;
    @Value("${axiom.bootstrap.admin-password:}") private String adminPassword;

    public FirstTenantBootstrapRunner(
            FirstTenantIdentityBootstrapService identityBootstrap,
            TenantProvisioningService provisioning,
            ActiveTenantDirectory activeTenants,
            TenantNamespaceAdapter namespaces,
            PolicyBundleRepository policyBundles) {
        this.identityBootstrap = identityBootstrap;
        this.provisioning = provisioning;
        this.activeTenants = activeTenants;
        this.namespaces = namespaces;
        this.policyBundles = policyBundles;
    }

    @Override
    public void run(ApplicationArguments args) {
        FirstTenantIdentityBootstrapService.BootstrapIdentity identity =
                new FirstTenantIdentityBootstrapService.BootstrapIdentity(
                        tenantId, tenantName, tenantSlug, adminId, adminUsername, adminEmail, adminPassword);
        identityBootstrap.ensureExact(identity);

        String provisioningKey = "axiom-first-provision:" + tenantId;
        ProvisioningResult result = provisioning.provision(
                new ProvisioningRequest(tenantId, tenantName, tenantSlug), provisioningKey, adminId);
        if (!result.isActive()
                || !activeTenants.isActive(tenantId)
                || !namespaces.namespaceExists(tenantId)
                || result.policyVersion() == null
                || policyBundles.findById(result.policyVersion()).isEmpty()) {
            throw new IllegalStateException("first bootstrap identity succeeded but policy runtime is not ACTIVE");
        }
    }
}
