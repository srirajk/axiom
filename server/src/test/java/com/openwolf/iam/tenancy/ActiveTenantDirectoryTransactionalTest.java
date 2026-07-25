package com.openwolf.iam.tenancy;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.transaction.support.TransactionSynchronization;
import org.springframework.transaction.support.TransactionSynchronizationManager;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Axiom H4 — the in-memory active-tenant pointer advanced by a promotion compare-and-set is rolled back
 * WITH the JPA transaction. If the surrounding {@code @Transactional promote()} fails after the CAS
 * published but before commit, the live pointer must NOT stay diverged from the durable store (which is
 * rolled back with the transaction) until a restart {@code reload()}.
 *
 * <p>Without Docker/JPA we drive Spring's transaction-synchronization contract directly: open a
 * synchronization scope, run the CAS (which registers the compensation), model the JPA rollback by
 * discarding the durable save, then fire {@code afterCompletion(STATUS_ROLLED_BACK)} and assert the live
 * pointer was compensated back to match the durable store.
 */
class ActiveTenantDirectoryTransactionalTest {

    @AfterEach
    void cleanup() {
        if (TransactionSynchronizationManager.isSynchronizationActive()) {
            TransactionSynchronizationManager.clearSynchronization();
        }
    }

    @Test
    void postCasRollbackCompensatesTheLivePointer() {
        // Durable store: a map that models the JPA-backed active_tenants table.
        Map<String, ActiveTenant> durable = new ConcurrentHashMap<>();
        ActiveTenantRepository repo = mock(ActiveTenantRepository.class);
        when(repo.save(any(ActiveTenant.class))).thenAnswer(a -> {
            ActiveTenant t = a.getArgument(0);
            durable.put(t.getTenantId(), t);
            return t;
        });
        when(repo.findAll()).thenAnswer(a -> new ArrayList<>(durable.values()));

        ActiveTenantDirectory dir = new ActiveTenantDirectory(repo);

        // Start on v0 (a plain, non-transactional activation).
        dir.activate("meridian", "v0");
        ActiveTenant v0Row = durable.get("meridian"); // the durable row the txn would roll back to
        assertThat(dir.find("meridian")).hasValue("v0");

        // ── The promotion transaction begins ──
        TransactionSynchronizationManager.initSynchronization();
        dir.compareAndActivate("meridian", "v0", "v1"); // CAS: in-memory → v1, save(v1), compensation registered
        assertThat(dir.find("meridian")).hasValue("v1");

        // ── The JPA transaction ROLLS BACK after the CAS: the durable save(v1) is discarded → back to v0. ──
        durable.put("meridian", v0Row);

        // Snapshot + deactivate the synchronizations exactly as the transaction manager does, then fire them.
        List<TransactionSynchronization> syncs = new ArrayList<>(TransactionSynchronizationManager.getSynchronizations());
        TransactionSynchronizationManager.clearSynchronization();

        // BEFORE compensation the live pointer (v1) diverges from the rolled-back durable store (v0).
        assertThat(dir.find("meridian")).hasValue("v1");
        assertThat(durable.get("meridian").getPolicyVersion()).isEqualTo("v0");

        syncs.forEach(s -> s.afterCompletion(TransactionSynchronization.STATUS_ROLLED_BACK));

        // AFTER compensation: the live pointer equals the durable store — no divergence.
        assertThat(dir.find("meridian")).hasValue("v0");
        assertThat(durable.get("meridian").getPolicyVersion()).isEqualTo("v0");
        // And a fresh reload from the durable store agrees (the pointer is not merely masked in memory).
        dir.reload();
        assertThat(dir.find("meridian")).hasValue("v0");
    }

    @Test
    void committedCasKeepsTheAdvancedPointer() {
        Map<String, ActiveTenant> durable = new ConcurrentHashMap<>();
        ActiveTenantRepository repo = mock(ActiveTenantRepository.class);
        when(repo.save(any(ActiveTenant.class))).thenAnswer(a -> {
            ActiveTenant t = a.getArgument(0);
            durable.put(t.getTenantId(), t);
            return t;
        });
        when(repo.findAll()).thenAnswer(a -> new ArrayList<>(durable.values()));

        ActiveTenantDirectory dir = new ActiveTenantDirectory(repo);
        dir.activate("meridian", "v0");

        TransactionSynchronizationManager.initSynchronization();
        dir.compareAndActivate("meridian", "v0", "v1");
        List<TransactionSynchronization> syncs = new ArrayList<>(TransactionSynchronizationManager.getSynchronizations());
        TransactionSynchronizationManager.clearSynchronization();

        // A COMMITTED transaction: no compensation runs; the advance stands and matches the durable store.
        syncs.forEach(s -> s.afterCompletion(TransactionSynchronization.STATUS_COMMITTED));

        assertThat(dir.find("meridian")).hasValue("v1");
        assertThat(durable.get("meridian").getPolicyVersion()).isEqualTo("v1");
    }

    @Test
    void activeRepositoryFailureCannotLeaveAStaleLivePointer() {
        Map<String, ActiveTenant> durable = new ConcurrentHashMap<>();
        ActiveTenantRepository repo = mock(ActiveTenantRepository.class);
        when(repo.save(any(ActiveTenant.class))).thenAnswer(a -> {
            ActiveTenant tenant = a.getArgument(0);
            if ("v1".equals(tenant.getPolicyVersion())) {
                throw new IllegalStateException("simulated active-tenant commit failure");
            }
            durable.put(tenant.getTenantId(), tenant);
            return tenant;
        });
        when(repo.findAll()).thenAnswer(a -> new ArrayList<>(durable.values()));

        ActiveTenantDirectory dir = new ActiveTenantDirectory(repo);
        dir.activate("meridian", "v0");
        TransactionSynchronizationManager.initSynchronization();
        assertThatThrownBy(() -> dir.compareAndActivate("meridian", "v0", "v1"))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("commit failure");

        List<TransactionSynchronization> syncs = new ArrayList<>(
                TransactionSynchronizationManager.getSynchronizations());
        TransactionSynchronizationManager.clearSynchronization();
        syncs.forEach(s -> s.afterCompletion(TransactionSynchronization.STATUS_ROLLED_BACK));

        assertThat(dir.find("meridian")).hasValue("v0");
        assertThat(durable.get("meridian").getPolicyVersion()).isEqualTo("v0");
    }

    @Test
    void deactivationRollbackRestoresTheLivePointer() {
        Map<String, ActiveTenant> durable = new ConcurrentHashMap<>();
        ActiveTenantRepository repo = mock(ActiveTenantRepository.class);
        when(repo.save(any(ActiveTenant.class))).thenAnswer(a -> {
            ActiveTenant tenant = a.getArgument(0);
            durable.put(tenant.getTenantId(), tenant);
            return tenant;
        });
        when(repo.findAll()).thenAnswer(a -> new ArrayList<>(durable.values()));
        ActiveTenantDirectory dir = new ActiveTenantDirectory(repo);
        dir.activate("meridian", "v0");

        TransactionSynchronizationManager.initSynchronization();
        dir.deactivate("meridian");
        assertThat(dir.find("meridian")).isEmpty();
        List<TransactionSynchronization> syncs = new ArrayList<>(
                TransactionSynchronizationManager.getSynchronizations());
        TransactionSynchronizationManager.clearSynchronization();
        syncs.forEach(s -> s.afterCompletion(TransactionSynchronization.STATUS_ROLLED_BACK));

        assertThat(dir.find("meridian")).hasValue("v0");
        assertThat(durable.get("meridian").getPolicyVersion()).isEqualTo("v0");
    }
}
