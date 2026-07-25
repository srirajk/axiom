package com.openwolf.iam.tenancy;

import com.openwolf.iam.entity.AuditLog;
import com.openwolf.iam.repository.AuditLogRepository;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;

/**
 * Axiom B4.3 — deprovision REVOKES access but RETAINS audit. After deprovision every gate denies (the
 * tenant is absent from the directory), the non-audit artifacts are cleaned, but the audit partition
 * still exists and is exportable (A6), and the policy bundles are retained for evidence.
 */
class DeprovisioningTest {

    private static final String TENANT = "acme";

    @Test
    void revokesAccessButRetainsAudit(@TempDir Path staging) {
        ActiveTenantDirectory directory = new ActiveTenantDirectory(ProvisioningTestSupport.activeRepo());
        InProcessTenantNamespaceAdapter namespace = new InProcessTenantNamespaceAdapter();
        AuditLogRepository auditRepo = ProvisioningTestSupport.auditRepo();
        PersistentAuditPartitionAdapter audit = new PersistentAuditPartitionAdapter(auditRepo);

        TenantProvisioningService service = new TenantProvisioningService(
                ProvisioningTestSupport.opsRepo(), directory,
                ProvisioningTestSupport.realPolicyAdapterNoProbe(staging),
                namespace, audit, ProvisioningTestSupport.acceptingPublisher(), ProvisioningTestSupport.tenantRepo());

        // Provision → ACTIVE, all artifacts present.
        ProvisioningResult provisioned = service.provision(
                new ProvisioningRequest(TENANT, "Acme", "acme"), "prov-key", "admin@bank");
        assertThat(provisioned.isActive()).isTrue();
        assertThat(directory.isActive(TENANT)).isTrue();
        assertThat(namespace.namespaceExists(TENANT)).isTrue();
        assertThat(audit.partitionExists(TENANT)).isTrue();

        // Deprovision.
        service.deprovision(TENANT, "deprov-key", "admin@bank");

        // Every gate denies: the tenant is gone from the directory (fail closed at A2).
        assertThat(directory.isActive(TENANT)).isFalse();
        assertThat(directory.find(TENANT)).isEmpty();

        // Non-audit artifacts were cleaned up (only AFTER the directory revoke + ack).
        assertThat(namespace.namespaceExists(TENANT)).as("redis namespace cleaned").isFalse();

        // The audit partition is RETAINED and still exportable (A6), with both lifecycle events.
        assertThat(audit.partitionExists(TENANT)).as("audit partition retained").isTrue();
        List<AuditLog> export = audit.export(TENANT);
        assertThat(export).as("post-deprovision audit export").isNotEmpty();
        assertThat(export).extracting(AuditLog::getAction)
                .contains("tenant.provisioned", "tenant.deprovisioned");

        // Structurally never deleted — no delete of the audit partition is ever issued.
        verify(auditRepo, never()).deleteById(any());
        verify(auditRepo, never()).delete(any());
        verify(auditRepo, never()).deleteAll();
    }

    @Test
    void deprovisionIsIdempotent(@TempDir Path staging) {
        ActiveTenantDirectory directory = new ActiveTenantDirectory(ProvisioningTestSupport.activeRepo());
        TenantProvisioningService service = new TenantProvisioningService(
                ProvisioningTestSupport.opsRepo(), directory,
                ProvisioningTestSupport.realPolicyAdapterNoProbe(staging),
                new InProcessTenantNamespaceAdapter(),
                new PersistentAuditPartitionAdapter(ProvisioningTestSupport.auditRepo()),
                ProvisioningTestSupport.acceptingPublisher(), ProvisioningTestSupport.tenantRepo());

        service.provision(new ProvisioningRequest(TENANT, "Acme", "acme"), "p", "admin");
        service.deprovision(TENANT, "d", "admin");
        service.deprovision(TENANT, "d", "admin"); // same key → no-op, no throw

        assertThat(directory.isActive(TENANT)).isFalse();
    }
}
