package com.openwolf.iam.tenancy;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicBoolean;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.clearInvocations;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.mockito.Mockito.verifyNoInteractions;

/**
 * Axiom B4.1 / H6 — a half-provisioned tenant is FULLY UNUSABLE <b>and</b> leaves NO ORPHANED
 * ARTIFACTS. Inject a failure after 2 of the 3 artifacts; the tenant must be absent from the active
 * directory (a request under it fails closed at the A2 seam with zero I/O) AND the already-staged
 * non-audit artifacts (Redis namespace, staged policy bundle) must be COMPENSATED/CLEANED — not merely
 * left absent from the directory. Red if a partial tenant can do anything, or if an orphaned namespace
 * or staged policy bundle survives the failed run.
 */
class ProvisioningAtomicityTest {

    private static final String TENANT = "acme";

    @Test
    void halfProvisionedTenantIsFullyUnusableAndArtifactsCleaned(@TempDir Path staging) {
        ActiveTenantRepository activeRepo = ProvisioningTestSupport.activeRepo();
        ActiveTenantDirectory directory = new ActiveTenantDirectory(activeRepo);

        // POLICY + REDIS succeed; AUDIT (artifact 3) fails → exactly 2 of 3 staged.
        InProcessTenantNamespaceAdapter namespaceAdapter = new InProcessTenantNamespaceAdapter();
        PolicyBootstrapAdapter policyAdapter = ProvisioningTestSupport.realPolicyAdapterNoProbe(staging);
        AuditPartitionAdapter failingAudit = new ProvisioningTestSupport.FailingAuditAdapter(
                new PersistentAuditPartitionAdapter(ProvisioningTestSupport.auditRepo()), 1);

        TenantProvisioningService service = new TenantProvisioningService(
                ProvisioningTestSupport.opsRepo(),
                directory,
                policyAdapter,
                namespaceAdapter,
                failingAudit,
                ProvisioningTestSupport.acceptingPublisher(), ProvisioningTestSupport.tenantRepo());

        assertThatThrownBy(() -> service.provision(
                new ProvisioningRequest(TENANT, "Acme Bank", "acme"), "key-atomic-1", "admin@bank"))
                .isInstanceOf(ProvisioningException.class);

        // The ledger recorded exactly the two artifacts that completed before the failure.
        ProvisioningOperation op = service.latestOperation(TENANT).orElseThrow();
        assertThat(op.getStatus()).isEqualTo(ProvisioningOperation.Status.FAILED);
        assertThat(op.stagedArtifacts()).containsExactlyInAnyOrder(
                ProvisioningOperation.Artifact.POLICY, ProvisioningOperation.Artifact.REDIS);
        assertThat(op.stagedArtifacts()).doesNotContain(
                ProvisioningOperation.Artifact.AUDIT);

        // The tenant is NOT in the directory — it can do NOTHING.
        assertThat(directory.isActive(TENANT)).isFalse();
        assertThat(directory.find(TENANT)).isEmpty();
        assertThat(directory.snapshot().tenantPolicyVersions()).doesNotContainKey(TENANT);

        // H6 — the staged artifacts were COMPENSATED, not merely left absent from the directory. The
        // ledger above proves POLICY + REDIS were genuinely staged; these prove they were then cleaned.
        assertThat(namespaceAdapter.namespaceExists(TENANT))
                .as("the staged Redis namespace must be compensated on a failed provision — "
                        + "an orphaned namespace must FAIL this test")
                .isFalse();
        assertThat(Files.exists(staging.resolve(TENANT)))
                .as("the staged policy bundle must be compensated on a failed provision — "
                        + "an orphaned staging directory must FAIL this test")
                .isFalse();

        // Fail-closed at A2 with ZERO I/O: the lookup reads only the in-memory snapshot; the durable
        // directory repository is never touched on a resolve.
        clearInvocations(activeRepo);
        assertThat(directory.find(TENANT)).isEmpty();
        assertThat(directory.find(TENANT)).isEmpty();
        verifyNoInteractions(activeRepo);
    }

    @Test
    void everyStageFailurePointLeavesTheTenantAbsent(@TempDir Path staging) {
        // Whichever single artifact fails, the tenant never becomes visible.
        for (int failAt = 0; failAt < 3; failAt++) {
            ActiveTenantDirectory directory = new ActiveTenantDirectory(ProvisioningTestSupport.activeRepo());
            PolicyBootstrapAdapter policy = ProvisioningTestSupport.realPolicyAdapterNoProbe(staging.resolve("s" + failAt));
            TenantNamespaceAdapter ns = new InProcessTenantNamespaceAdapter();
            AuditPartitionAdapter audit = new PersistentAuditPartitionAdapter(ProvisioningTestSupport.auditRepo());

            switch (failAt) {
                case 0 -> policy = new ProvisioningTestSupport.FailingPolicyAdapter(policy, 1);
                case 1 -> ns = new ProvisioningTestSupport.FailingNamespaceAdapter(ns, 1);
                case 2 -> audit = new ProvisioningTestSupport.FailingAuditAdapter(audit, 1);
                default -> { }
            }
            TenantProvisioningService service = new TenantProvisioningService(
                    ProvisioningTestSupport.opsRepo(), directory, policy, ns, audit,
                    ProvisioningTestSupport.acceptingPublisher(), ProvisioningTestSupport.tenantRepo());

            String tenant = "t" + failAt;
            String key = "k-" + failAt;
            TenantProvisioningService svc = service;
            assertThatThrownBy(() -> svc.provision(
                    new ProvisioningRequest(tenant, tenant, tenant), key, "admin"))
                    .isInstanceOf(ProvisioningException.class);
            assertThat(directory.isActive(tenant))
                    .as("tenant must be absent when artifact %d fails", failAt).isFalse();
        }
    }

    @Test
    void failureAfterDirectoryCasPreservesDependenciesAndRetryReconciles(@TempDir Path staging) {
        Map<String, ProvisioningOperation> byKey = new HashMap<>();
        AtomicBoolean failActiveSaveOnce = new AtomicBoolean(true);
        ProvisioningOperationRepository operations = mock(ProvisioningOperationRepository.class);
        when(operations.findByIdempotencyKey(anyString()))
                .thenAnswer(a -> Optional.ofNullable(byKey.get(a.<String>getArgument(0))));
        when(operations.save(any(ProvisioningOperation.class))).thenAnswer(a -> {
            ProvisioningOperation op = a.getArgument(0);
            if (op.getStatus() == ProvisioningOperation.Status.ACTIVE
                    && failActiveSaveOnce.compareAndSet(true, false)) {
                throw new IllegalStateException("injected post-CAS ACTIVE ledger failure");
            }
            byKey.put(op.getIdempotencyKey(), op);
            return op;
        });

        ActiveTenantDirectory directory = new ActiveTenantDirectory(ProvisioningTestSupport.activeRepo());
        InProcessTenantNamespaceAdapter namespace = new InProcessTenantNamespaceAdapter();
        TenantProvisioningService service = new TenantProvisioningService(
                operations, directory, ProvisioningTestSupport.realPolicyAdapterNoProbe(staging),
                namespace,
                new PersistentAuditPartitionAdapter(ProvisioningTestSupport.auditRepo()),
                ProvisioningTestSupport.acceptingPublisher(), ProvisioningTestSupport.tenantRepo());

        ProvisioningRequest request = new ProvisioningRequest(TENANT, "Acme", "acme");
        assertThatThrownBy(() -> service.provision(request, "post-cas-key", "admin"))
                .isInstanceOf(ProvisioningException.class)
                .hasMessageContaining("provisioning failed");

        assertThat(directory.find(TENANT)).hasValueSatisfying(v -> assertThat(v).startsWith("b_"));
        assertThat(namespace.namespaceExists(TENANT)).isTrue();
        assertThat(Files.isDirectory(staging.resolve(TENANT))).isTrue();

        ProvisioningResult reconciled = service.provision(request, "post-cas-key", "admin");
        assertThat(reconciled.isActive()).isTrue();
        assertThat(directory.find(TENANT)).contains(reconciled.policyVersion());
        assertThat(namespace.namespaceExists(TENANT)).isTrue();
    }

    @Test
    void runtimePublicationFailureNeverActivatesAndCompensatesDependencies(@TempDir Path staging) {
        ActiveTenantDirectory directory = new ActiveTenantDirectory(ProvisioningTestSupport.activeRepo());
        InProcessTenantNamespaceAdapter namespace = new InProcessTenantNamespaceAdapter();
        TenantProvisioningService service = new TenantProvisioningService(
                ProvisioningTestSupport.opsRepo(), directory,
                ProvisioningTestSupport.realPolicyAdapterNoProbe(staging), namespace,
                new PersistentAuditPartitionAdapter(ProvisioningTestSupport.auditRepo()),
                bundle -> { throw new ProvisioningException("injected runtime publication failure"); },
                ProvisioningTestSupport.tenantRepo());

        assertThatThrownBy(() -> service.provision(
                new ProvisioningRequest(TENANT, "Acme", "acme"), "runtime-fail-key", "admin"))
                .isInstanceOf(ProvisioningException.class)
                .hasMessageContaining("runtime publication failure");

        assertThat(directory.find(TENANT)).isEmpty();
        assertThat(namespace.namespaceExists(TENANT)).isFalse();
        assertThat(Files.exists(staging.resolve(TENANT))).isFalse();
    }
}
