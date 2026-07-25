package com.openwolf.iam.tenancy;

import com.openwolf.iam.entity.AuditLog;
import com.openwolf.iam.entity.Tenant;
import com.openwolf.iam.policystudio.CanonicalPolicyWriter;
import com.openwolf.iam.policystudio.CerbosCompileGate;
import com.openwolf.iam.repository.AuditLogRepository;
import com.openwolf.iam.repository.TenantRepository;
import com.openwolf.iam.test.AxiomTestPolicyRoot;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Shared wiring for the B4 provisioning harness. Builds a {@link TenantProvisioningService} over
 * stateful in-memory repository mocks and the REAL adapters, so the tests exercise the true
 * orchestration, atomicity, idempotency, and cleanup-ordering logic (no fake service). Failure is
 * injected via thin decorators that fail an artifact's first N calls, then delegate.
 */
final class ProvisioningTestSupport {

    private ProvisioningTestSupport() {}

    /** Resolve only the isolated Axiom platform-policy package. */
    static Path baseBundleDir() {
        return AxiomTestPolicyRoot.policies();
    }

    static CerbosPolicyBootstrapAdapter realPolicyAdapter(Path stagingRoot) {
        return new CerbosPolicyBootstrapAdapter(
                new CanonicalPolicyWriter(),
                new CerbosCompileGate(AxiomTestPolicyRoot.cerbosImage(), 60),
                baseBundleDir().toString(),
                stagingRoot.toAbsolutePath().toString());
    }

    /**
     * The real adapter for the staging half (content-addressed deny-all bundle written to disk) but
     * with the Cerbos compile probe skipped — orchestration/atomicity/retry tests exercise the flip
     * logic, not the PDP. The dedicated {@code freshTenantBootstrapDeniesEverything} test probes for real.
     */
    static PolicyBootstrapAdapter realPolicyAdapterNoProbe(Path stagingRoot) {
        CerbosPolicyBootstrapAdapter real = realPolicyAdapter(stagingRoot);
        return new PolicyBootstrapAdapter() {
            @Override public TenantBootstrapBundle stage(String tenantId) { return real.stage(tenantId); }
            @Override public void probe(TenantBootstrapBundle b) { /* Cerbos probe skipped here */ }
            @Override public boolean isProbeAvailable() { return false; }
            // Delegate H6 compensation to the real disk-staging adapter so cleanup is genuinely exercised.
            @Override public void discardStaged(TenantBootstrapBundle b) { real.discardStaged(b); }
        };
    }

    /** A stateful in-memory {@link ProvisioningOperationRepository} (find-by-key + save). */
    static ProvisioningOperationRepository opsRepo() {
        Map<String, ProvisioningOperation> byKey = new HashMap<>();
        ProvisioningOperationRepository repo = mock(ProvisioningOperationRepository.class);
        when(repo.findByIdempotencyKey(anyString()))
                .thenAnswer(a -> Optional.ofNullable(byKey.get(a.<String>getArgument(0))));
        when(repo.save(any(ProvisioningOperation.class))).thenAnswer(a -> {
            ProvisioningOperation op = a.getArgument(0);
            byKey.put(op.getIdempotencyKey(), op);
            return op;
        });
        when(repo.findByTenantIdOrderByCreatedAtDesc(anyString())).thenAnswer(a -> byKey.values().stream()
                .filter(o -> o.getTenantId().equals(a.<String>getArgument(0)))
                .toList());
        return repo;
    }

    static ActiveTenantRepository activeRepo() {
        // findAll() defaults to an empty list; the directory keeps its own in-memory snapshot, so
        // save/deleteById can be no-op mocks. Kept as a field so tests can verify zero-I/O on lookup.
        return mock(ActiveTenantRepository.class);
    }

    /** Stateful catalogue fake: it is deliberately independent from active-directory serving authority. */
    static TenantRepository tenantRepo() {
        Map<String, Tenant> byId = new HashMap<>();
        TenantRepository repo = mock(TenantRepository.class);
        when(repo.findById(anyString())).thenAnswer(a -> Optional.ofNullable(byId.get(a.<String>getArgument(0))));
        when(repo.findBySlug(anyString())).thenAnswer(a -> byId.values().stream()
                .filter(tenant -> tenant.getSlug().equals(a.<String>getArgument(0))).findFirst());
        when(repo.save(any(Tenant.class))).thenAnswer(a -> {
            Tenant tenant = a.getArgument(0);
            byId.put(tenant.getId(), tenant);
            return tenant;
        });
        return repo;
    }

    static BootstrapPolicyPublisher acceptingPublisher() {
        return bundle -> {
            if (!bundle.bundleId().startsWith("b_") || bundle.renderedFiles().isEmpty()) {
                throw new ProvisioningException("test publisher received an invalid bootstrap bundle");
            }
        };
    }

    /** A stateful in-memory {@link AuditLogRepository} for the REAL audit adapter (A6). */
    static AuditLogRepository auditRepo() {
        List<AuditLog> logs = Collections.synchronizedList(new ArrayList<>());
        AuditLogRepository repo = mock(AuditLogRepository.class);
        when(repo.save(any(AuditLog.class))).thenAnswer(a -> {
            AuditLog l = a.getArgument(0);
            logs.add(l);
            return l;
        });
        when(repo.findByTenantIdOrderByOccurredAtDesc(anyString())).thenAnswer(a -> logs.stream()
                .filter(l -> l.getTenantId().equals(a.<String>getArgument(0)))
                .toList());
        return repo;
    }

    // ── failure-injecting decorators ───────────────────────────────────────────────────────────

    /** Fails the first {@code failFirst} calls to the guarded artifact, then delegates. */
    static final class FailingPolicyAdapter implements PolicyBootstrapAdapter {
        private final PolicyBootstrapAdapter delegate;
        private int failFirst;
        FailingPolicyAdapter(PolicyBootstrapAdapter delegate, int failFirst) {
            this.delegate = delegate; this.failFirst = failFirst;
        }
        @Override public TenantBootstrapBundle stage(String tenantId) {
            if (failFirst-- > 0) throw new ProvisioningException("injected POLICY stage failure");
            return delegate.stage(tenantId);
        }
        @Override public void probe(TenantBootstrapBundle b) { delegate.probe(b); }
        @Override public boolean isProbeAvailable() { return delegate.isProbeAvailable(); }
        @Override public void discardStaged(TenantBootstrapBundle b) { delegate.discardStaged(b); }
    }

    static final class FailingNamespaceAdapter implements TenantNamespaceAdapter {
        private final TenantNamespaceAdapter delegate;
        private int failFirst;
        FailingNamespaceAdapter(TenantNamespaceAdapter delegate, int failFirst) {
            this.delegate = delegate; this.failFirst = failFirst;
        }
        @Override public String createNamespace(String tenantId) {
            if (failFirst-- > 0) throw new ProvisioningException("injected REDIS stage failure");
            return delegate.createNamespace(tenantId);
        }
        @Override public boolean namespaceExists(String t) { return delegate.namespaceExists(t); }
        @Override public void removeNamespace(String t) { delegate.removeNamespace(t); }
    }

    static final class FailingAuditAdapter implements AuditPartitionAdapter {
        private final AuditPartitionAdapter delegate;
        private int failFirst;
        FailingAuditAdapter(AuditPartitionAdapter delegate, int failFirst) {
            this.delegate = delegate; this.failFirst = failFirst;
        }
        @Override public void recordProvisioned(String t, String a, String c) {
            if (failFirst-- > 0) throw new ProvisioningException("injected AUDIT stage failure");
            delegate.recordProvisioned(t, a, c);
        }
        @Override public void recordDeprovisioned(String t, String a, String c) { delegate.recordDeprovisioned(t, a, c); }
        @Override public void recordLifecycleLockRecoveryEvent(String t, String a, String action,
                                                               String c, String payload) {
            delegate.recordLifecycleLockRecoveryEvent(t, a, action, c, payload);
        }
        @Override public boolean partitionExists(String t) { return delegate.partitionExists(t); }
        @Override public List<AuditLog> export(String t) { return delegate.export(t); }
    }
}
