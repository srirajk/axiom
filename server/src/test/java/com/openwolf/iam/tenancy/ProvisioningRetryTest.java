package com.openwolf.iam.tenancy;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Axiom B4.5 — a failure at ANY stage reconciles idempotently. Inject a failure after each stage in
 * turn; a retry with the SAME idempotency key yields exactly one active tenant and no conflicting
 * policy/index artifacts (content-addressed policy version + idempotent adapters).
 */
class ProvisioningRetryTest {

    @Test
    void failureIsIdempotentlyReconciled(@TempDir Path stagingRoot) throws IOException {
        for (int failAt = 0; failAt < 3; failAt++) {
            String tenant = "acme" + failAt;
            String key = "retry-key-" + failAt;
            Path staging = stagingRoot.resolve("scenario" + failAt);

            ActiveTenantDirectory directory = new ActiveTenantDirectory(ProvisioningTestSupport.activeRepo());
            ProvisioningOperationRepository ops = ProvisioningTestSupport.opsRepo();

            // Decorators that fail exactly ONCE at the targeted stage, then delegate on the retry.
            PolicyBootstrapAdapter policy = ProvisioningTestSupport.realPolicyAdapterNoProbe(staging);
            TenantNamespaceAdapter ns = new InProcessTenantNamespaceAdapter();
            AuditPartitionAdapter audit = new PersistentAuditPartitionAdapter(ProvisioningTestSupport.auditRepo());
            switch (failAt) {
                case 0 -> policy = new ProvisioningTestSupport.FailingPolicyAdapter(policy, 1);
                case 1 -> ns = new ProvisioningTestSupport.FailingNamespaceAdapter(ns, 1);
                case 2 -> audit = new ProvisioningTestSupport.FailingAuditAdapter(audit, 1);
                default -> { }
            }
            TenantProvisioningService service =
                    new TenantProvisioningService(ops, directory, policy, ns, audit,
                            ProvisioningTestSupport.acceptingPublisher(), ProvisioningTestSupport.tenantRepo());

            // Attempt 1 fails at the injected stage — tenant stays absent.
            assertThatThrownBy(() -> service.provision(
                    new ProvisioningRequest(tenant, tenant, tenant), key, "admin"))
                    .as("attempt 1 fails at stage %d", failAt)
                    .isInstanceOf(ProvisioningException.class);
            assertThat(directory.isActive(tenant)).isFalse();

            // Attempt 2 (same key) resumes and reconciles → exactly one active tenant.
            ProvisioningResult retry = service.provision(
                    new ProvisioningRequest(tenant, tenant, tenant), key, "admin");
            assertThat(retry.isActive()).as("retry at stage %d reconciles to ACTIVE", failAt).isTrue();
            assertThat(directory.isActive(tenant)).isTrue();
            assertThat(directory.snapshot().tenantPolicyVersions()).hasSize(1);

            // No conflicting artifacts: exactly one content-addressed policy version was staged.
            Path tenantStaging = staging.resolve(tenant);
            try (Stream<Path> versions = Files.list(tenantStaging)) {
                assertThat(versions.toList())
                        .as("retry must not fork a second policy version for '%s'", tenant)
                        .hasSize(1);
            }

            // The ledger converged on a single ACTIVE operation for this key.
            assertThat(ops.findByIdempotencyKey(key)).get()
                    .extracting(ProvisioningOperation::getStatus)
                    .isEqualTo(ProvisioningOperation.Status.ACTIVE);
            assertThat(service.latestOperation(tenant)).get()
                    .extracting(ProvisioningOperation::getPolicyVersion)
                    .isEqualTo(retry.policyVersion());
        }
    }
}
