package com.openwolf.iam.tenancy;

import com.openwolf.iam.entity.Tenant;
import com.openwolf.iam.repository.TenantRepository;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class TenantCatalogProvisioningTest {

    @Test
    void persistsExactCatalogIdentityReconcilesReplayAndRetainsItAfterDeprovision(@TempDir Path staging) {
        TenantRepository tenants = ProvisioningTestSupport.tenantRepo();
        ActiveTenantDirectory directory = new ActiveTenantDirectory(ProvisioningTestSupport.activeRepo());
        TenantProvisioningService service = service(staging, directory, tenants);
        ProvisioningRequest request = new ProvisioningRequest("tenant-a", "Tenant A", "tenant-a");

        service.provision(request, "create", "admin");
        Tenant tenant = tenants.findById("tenant-a").orElseThrow();
        assertThat(tenant.getName()).isEqualTo("Tenant A");
        assertThat(tenant.getSlug()).isEqualTo("tenant-a");

        assertThat(service.provision(request, "replay", "admin").isActive()).isTrue();
        service.deprovision("tenant-a", "deprovision", "admin");

        assertThat(directory.isActive("tenant-a")).isFalse();
        assertThat(tenants.findById("tenant-a")).containsSame(tenant);
    }

    @Test
    void rejectsConflictingTenantMetadataOrSlugWithoutActivatingAnotherTenant(@TempDir Path staging) {
        TenantRepository tenants = ProvisioningTestSupport.tenantRepo();
        ActiveTenantDirectory directory = new ActiveTenantDirectory(ProvisioningTestSupport.activeRepo());
        TenantProvisioningService service = service(staging, directory, tenants);
        service.provision(new ProvisioningRequest("tenant-a", "Tenant A", "tenant-a"), "create", "admin");

        assertThatThrownBy(() -> service.provision(
                new ProvisioningRequest("tenant-a", "Renamed", "tenant-a"), "conflicting-name", "admin"))
                .isInstanceOf(ProvisioningException.class).hasMessageContaining("conflicting name or slug");
        assertThatThrownBy(() -> service.provision(
                new ProvisioningRequest("tenant-b", "Tenant B", "tenant-a"), "conflicting-slug", "admin"))
                .isInstanceOf(ProvisioningException.class).hasMessageContaining("slug");

        assertThat(directory.isActive("tenant-a")).isTrue();
        assertThat(directory.isActive("tenant-b")).isFalse();
        assertThat(tenants.findById("tenant-b")).isEmpty();
    }

    private static TenantProvisioningService service(Path staging, ActiveTenantDirectory directory,
                                                      TenantRepository tenants) {
        return new TenantProvisioningService(ProvisioningTestSupport.opsRepo(), directory,
                ProvisioningTestSupport.realPolicyAdapterNoProbe(staging), new InProcessTenantNamespaceAdapter(),
                new PersistentAuditPartitionAdapter(ProvisioningTestSupport.auditRepo()),
                ProvisioningTestSupport.acceptingPublisher(), tenants);
    }
}
