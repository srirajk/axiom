package com.openwolf.iam.tenancy;

import jakarta.annotation.PostConstruct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionSynchronization;
import org.springframework.transaction.support.TransactionSynchronizationManager;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;

/**
 * The authoritative active-tenant directory (Axiom Story B4). Membership here means a tenant is
 * fully provisioned and visible; a tenant is added ONLY by the activation compare-and-set (the last
 * step of a provision, after all three artifacts verify) and removed FIRST on deprovision.
 *
 * <p>This is the IAM-side serving directory: an immutable, versioned {@code tenantId → policyVersion}
 * map behind an {@link AtomicReference}. A serving replica may obtain its read snapshot by polling the
 * directory snapshot out of band ({@code TenantSnapshotSource}); a whole, consistent snapshot is
 * published atomically and a stale version is ignored. The {@link #find} lookup performs <b>zero
 * I/O</b> — it reads only the in-memory reference — so a half-provisioned or deprovisioned tenant
 * (absent from the map) resolves as unknown and fails closed without ever touching Postgres or Redis.
 *
 * <p>{@link ActiveTenantRepository} is the durable backing, loaded once at startup and written only
 * on the activate/deactivate CAS — never on a read.
 */
@Component
public class ActiveTenantDirectory {

    private static final Logger log = LoggerFactory.getLogger(ActiveTenantDirectory.class);

    /** Immutable, versioned view — the exact shape a serving replica may mirror. */
    public record Snapshot(long version, Map<String, String> tenantPolicyVersions) {
        public Snapshot {
            tenantPolicyVersions = Map.copyOf(tenantPolicyVersions);
        }
    }

    private final ActiveTenantRepository repository;
    private final AtomicReference<Snapshot> current = new AtomicReference<>(new Snapshot(0L, Map.of()));
    private final AtomicLong versionSeq = new AtomicLong(0L);

    public ActiveTenantDirectory(ActiveTenantRepository repository) {
        this.repository = repository;
    }

    /** Seed the in-memory snapshot from the durable set (startup). Control-plane I/O, never on a read. */
    @PostConstruct
    public void reload() {
        Map<String, String> map = new LinkedHashMap<>();
        for (ActiveTenant t : repository.findAll()) {
            map.put(t.getTenantId(), t.getPolicyVersion());
        }
        long version = nextVersion();
        current.set(new Snapshot(version, map));
        log.info("Active-tenant directory loaded: {} active tenant(s) (snapshot v{})", map.size(), version);
    }

    /**
     * The activation compare-and-set — the LAST step of a provision. Durably records the tenant then
     * atomically publishes a new snapshot that includes it. Idempotent: re-activating an
     * already-active tenant with the same policy version republishes the same membership.
     *
     * @return the published snapshot version.
     */
    @Transactional
    public long activate(String tenantId, String policyVersion) {
        long version = nextVersion();
        repository.save(new ActiveTenant(tenantId, policyVersion, version));
        Snapshot published = current.updateAndGet(prev -> {
            Map<String, String> next = new LinkedHashMap<>(prev.tenantPolicyVersions());
            next.put(tenantId, policyVersion);
            return new Snapshot(version, next);
        });
        log.info("Activated tenant '{}' (policyVersion={}) — directory snapshot v{} ({} tenants)",
                tenantId, policyVersion, published.version(), published.tenantPolicyVersions().size());
        return published.version();
    }

    /**
     * The deactivation compare-and-set — the FIRST step of a deprovision. Removes the tenant from the
     * durable set and publishes a snapshot without it, so every subsequent request under the
     * tenant fails closed. Non-audit artifact cleanup happens only AFTER this and the directory-version
     * ack. Idempotent: deactivating an absent tenant still bumps the version (a no-op membership).
     *
     * @return the published snapshot version (serving replicas must acknowledge it before cleanup).
     */
    @Transactional
    public long deactivate(String tenantId) {
        Snapshot before = current.get();
        long version = nextVersion();
        repository.deleteById(tenantId);
        Snapshot published = current.updateAndGet(prev -> {
            Map<String, String> next = new LinkedHashMap<>(prev.tenantPolicyVersions());
            next.remove(tenantId);
            return new Snapshot(version, next);
        });
        registerRollbackCompensation(tenantId, before, published);
        log.info("Deactivated tenant '{}' — directory snapshot v{} ({} tenants); requests now fail closed",
                tenantId, published.version(), published.tenantPolicyVersions().size());
        return published.version();
    }

    /**
     * The policy-promotion compare-and-set (Axiom Story C5). Atomically advances a tenant's active
     * policy version from an EXACT expected old id to a new id — the SAME live pointer B4's activation
     * flips, so a promotion cannot introduce a second source of truth. This is the last step of a
     * promotion: the candidate bundle has already been staged, compiled, loaded and invariant-probed at
     * {@code toPolicyVersion}; only now does it become visible.
     *
     * <p>Fails (throws) if the tenant's current active version is not {@code expectedFromPolicyVersion} —
     * i.e. the reviewed baseline was superseded by another promotion after the C4 review. The candidate
     * then stays inactive and a fresh diff/approval against the new current bundle is required (C5.5).
     * Retries internally on a benign concurrent snapshot swap, re-checking the precondition each time.
     *
     * @param tenantId                  the tenant whose active version advances
     * @param expectedFromPolicyVersion the reviewed OLD id the CAS must observe ({@code null} ⇒ tenant
     *                                  currently has no active version)
     * @param toPolicyVersion           the candidate bundle id to activate
     * @return the published directory snapshot version
     * @throws IllegalStateException if the current active version is not the expected old id (stale CAS)
     */
    @Transactional
    public long compareAndActivate(String tenantId, String expectedFromPolicyVersion, String toPolicyVersion) {
        if (tenantId == null || tenantId.isBlank()) {
            throw new IllegalArgumentException("tenantId must be set");
        }
        if (toPolicyVersion == null || toPolicyVersion.isBlank()) {
            throw new IllegalArgumentException("toPolicyVersion must be set");
        }
        while (true) {
            Snapshot prev = current.get();
            String actual = prev.tenantPolicyVersions().get(tenantId);
            if (!Objects.equals(actual, expectedFromPolicyVersion)) {
                throw new IllegalStateException(
                        "promotion compare-and-set for tenant '" + tenantId + "' failed: expected current "
                                + "policy version '" + expectedFromPolicyVersion + "' but the active version is now '"
                                + actual + "' — the reviewed baseline is stale; a fresh diff/approval is required");
            }
            long version = nextVersion();
            Map<String, String> next = new LinkedHashMap<>(prev.tenantPolicyVersions());
            next.put(tenantId, toPolicyVersion);
            Snapshot updated = new Snapshot(version, next);
            if (current.compareAndSet(prev, updated)) {
                // (H4) The in-memory pointer advance must be undone WITH the JPA transaction. The
                // repository.save below is rolled back by JPA on failure, but this AtomicReference is not
                // transactional — so register a compensation that reverts the published snapshot to `prev`
                // before the durable write, so a commit failure cannot leave a live pointer with no row.
                registerRollbackCompensation(tenantId, prev, updated);
                repository.save(new ActiveTenant(tenantId, toPolicyVersion, version));
                log.info("Promoted tenant '{}' policy version {} → {} — directory snapshot v{}",
                        tenantId, expectedFromPolicyVersion, toPolicyVersion, version);
                return version;
            }
            // A concurrent snapshot swap won the CAS — re-read and re-check the precondition.
        }
    }

    /**
     * (H4) Register a transaction-scoped compensation for a published promotion CAS: if the surrounding
     * JPA transaction rolls back after this in-memory advance, revert the snapshot from {@code after} back
     * to {@code before}, so the live pointer stays consistent with the durable store (whose {@code save}
     * was rolled back with the transaction) instead of diverging until the next {@link #reload()}.
     *
     * <p>The revert is a guarded {@code compareAndSet(after, before)}: if a concurrent control-plane
     * operation already advanced the pointer past {@code after}, we do not clobber it (the durable store
     * remains the ultimate truth, reconciled on the next reload) and log that the compensation could not
     * apply. Under the single-writer control plane the guarded revert restores the exact prior snapshot.
     */
    private void registerRollbackCompensation(String tenantId, Snapshot before, Snapshot after) {
        if (!TransactionSynchronizationManager.isSynchronizationActive()) {
            return; // no transaction to bind to — a direct (non-transactional) call, nothing to compensate
        }
        TransactionSynchronizationManager.registerSynchronization(new TransactionSynchronization() {
            @Override
            public void afterCompletion(int status) {
                if (status != STATUS_ROLLED_BACK) {
                    return;
                }
                boolean reverted = current.compareAndSet(after, before);
                log.warn("Directory transaction ROLLED BACK — {} the active-tenant pointer for '{}' from "
                                + "snapshot v{} back to v{} (durable store save was rolled back with the txn)",
                        reverted ? "compensated" : "could NOT compensate (pointer advanced concurrently);",
                        tenantId, after.version(), before.version());
            }
        });
    }

    /** Zero-I/O lookup — reads only the in-memory snapshot. Absent ⇒ unknown ⇒ fail closed. */
    public Optional<String> find(String tenantId) {
        if (tenantId == null) return Optional.empty();
        return Optional.ofNullable(current.get().tenantPolicyVersions().get(tenantId));
    }

    public boolean isActive(String tenantId) {
        return find(tenantId).isPresent();
    }

    /** The current published snapshot — what serving replicas may install out of band. */
    public Snapshot snapshot() {
        return current.get();
    }

    public long version() {
        return current.get().version();
    }

    private long nextVersion() {
        // Monotonic and unique even across restarts: seed from wall clock, then always advance.
        long candidate = System.currentTimeMillis();
        return versionSeq.updateAndGet(prev -> Math.max(prev + 1, candidate));
    }
}
