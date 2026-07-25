package com.openwolf.iam.tenancy;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import jakarta.annotation.PreDestroy;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Durable BUSY ownership for the tenant lifecycle saga. A PostgreSQL session advisory lock spans
 * external staging calls, while each database transition remains short and transactional. The row
 * is deliberately not automatically overwritten after {@code lease_until}: a crashed process leaves
 * the tenant unavailable until an explicit, audited two-person reconciliation proves the directory,
 * runtime, Redis and audit state are safe to clear.
 */
@Component
public class TenantLifecycleLockStore {

    private final JdbcTemplate jdbc;
    private final long leaseSeconds;
    private final boolean noOp;
    private final ScheduledExecutorService heartbeatExecutor;
    private final AuditPartitionAdapter audit;
    private final LifecycleLockReconciliationLedger reconciliation;

    @Autowired
    public TenantLifecycleLockStore(
            JdbcTemplate jdbc,
            @Value("${axiom.provisioning.lock-lease-seconds:900}") long leaseSeconds,
            AuditPartitionAdapter audit,
            LifecycleLockReconciliationLedger reconciliation) {
        this(jdbc, leaseSeconds, audit, reconciliation, false);
    }

    /** Direct constructor retained for real-Postgres integration tests. */
    public TenantLifecycleLockStore(JdbcTemplate jdbc, long leaseSeconds) {
        this(jdbc, leaseSeconds, null, null, false);
    }

    private TenantLifecycleLockStore(JdbcTemplate jdbc, long leaseSeconds,
                                     AuditPartitionAdapter audit,
                                     LifecycleLockReconciliationLedger reconciliation,
                                     boolean noOp) {
        this.jdbc = jdbc;
        this.leaseSeconds = Math.max(30L, leaseSeconds);
        this.noOp = noOp;
        this.audit = audit;
        this.reconciliation = reconciliation;
        ThreadFactory factory = runnable -> {
            Thread thread = new Thread(runnable, "axiom-tenant-lifecycle-heartbeat");
            thread.setDaemon(true);
            return thread;
        };
        this.heartbeatExecutor = Executors.newSingleThreadScheduledExecutor(factory);
    }

    private TenantLifecycleLockStore() {
        this.jdbc = null;
        this.leaseSeconds = 0L;
        this.noOp = true;
        this.heartbeatExecutor = null;
        this.audit = null;
        this.reconciliation = null;
    }

    static TenantLifecycleLockStore noOp() {
        return new TenantLifecycleLockStore();
    }

    public Lease acquire(String tenantId) {
        String ownerToken = UUID.randomUUID().toString();
        if (noOp) return new Lease(tenantId, ownerToken, null, null, new AtomicBoolean(false), null);
        Connection session = openAdvisorySession(tenantId);
        try {
            int changed = jdbc.update("""
                    INSERT INTO tenant_lifecycle_locks (tenant_id, owner_key, lease_until)
                    VALUES (?, ?, now() + (? * interval '1 second'))
                    ON CONFLICT (tenant_id) DO NOTHING
                    """, tenantId, ownerToken, leaseSeconds);
            if (changed != 1) {
                throw new ProvisioningException("tenant lifecycle is BUSY for '" + tenantId
                        + "'; automatic expiry takeover is disabled; reconcile the durable lock");
            }
        } catch (RuntimeException failure) {
            closeAdvisorySession(session, tenantId);
            throw failure;
        }
        AtomicBoolean lost = new AtomicBoolean(false);
        long heartbeatSeconds = Math.max(1L, leaseSeconds / 3L);
        ScheduledFuture<?> heartbeat = heartbeatExecutor.scheduleAtFixedRate(
                () -> renew(tenantId, ownerToken, lost), heartbeatSeconds, heartbeatSeconds, TimeUnit.SECONDS);
        return new Lease(tenantId, ownerToken, this, heartbeat, lost, session);
    }

    private void renew(String tenantId, String ownerToken, AtomicBoolean lost) {
        if (lost.get()) return;
        try {
            int changed = jdbc.update("""
                    UPDATE tenant_lifecycle_locks
                    SET lease_until = now() + (? * interval '1 second')
                    WHERE tenant_id = ? AND owner_key = ?
                    """, leaseSeconds, tenantId, ownerToken);
            if (changed != 1) lost.set(true);
        } catch (RuntimeException e) {
            lost.set(true);
        }
    }

    @PreDestroy
    void shutdown() {
        if (heartbeatExecutor != null) heartbeatExecutor.shutdownNow();
    }

    private void release(Lease lease) {
        if (lease.heartbeat() != null) lease.heartbeat().cancel(false);
        if (noOp) return;
        if (lease.lost()) {
            // Ownership is uncertain; ordinary close must preserve durable BUSY for reconciliation.
            closeAdvisorySession(lease.session(), lease.tenantId());
            return;
        }
        try {
            jdbc.update("DELETE FROM tenant_lifecycle_locks WHERE tenant_id = ? AND owner_key = ?",
                    lease.tenantId(), lease.ownerToken());
        } finally {
            closeAdvisorySession(lease.session(), lease.tenantId());
        }
    }

    /**
     * Explicit crash recovery. Expiry is diagnostic only; this operation is the sole path that can
     * clear a durable BUSY row after a process crash. The evidence is supplied by an operator and a
     * distinct approver after independently checking every mutable artifact. The guarded delete and
     * durable audit event commit together, so a retry is safe if the process dies during reconciliation.
     */
    boolean reconcileStale(String tenantId, String expectedOwner, ReconciliationEvidence evidence) {
        if (noOp) throw new ProvisioningException("lifecycle reconciliation is unavailable in test mode");
        evidence.validate();
        if (audit == null) throw new ProvisioningException("lifecycle reconciliation audit is not configured");
        if (reconciliation == null) {
            throw new ProvisioningException("lifecycle reconciliation boundary is not configured");
        }
        Connection session = openAdvisorySession(tenantId);
        try {
            return reconciliation.clearIfExpired(tenantId, expectedOwner, evidence);
        } finally {
            closeAdvisorySession(session, tenantId);
        }
    }

    Optional<LockObservation> inspect(String tenantId) {
        try {
            return Optional.ofNullable(jdbc.query("""
                    SELECT owner_key, lease_until FROM tenant_lifecycle_locks WHERE tenant_id = ?
                    """, result -> result.next()
                            ? new LockObservation(result.getString("owner_key"),
                            Optional.ofNullable(result.getTimestamp("lease_until"))
                                    .map(Timestamp::toInstant).orElseThrow())
                            : null, tenantId));
        } catch (RuntimeException failure) {
            throw new ProvisioningException("could not inspect tenant lifecycle lock for '" + tenantId + "'", failure);
        }
    }

    private Connection openAdvisorySession(String tenantId) {
        try {
            Connection session = java.util.Objects.requireNonNull(jdbc.getDataSource(),
                    "lifecycle lock JDBC datasource").getConnection();
            try (PreparedStatement statement = session.prepareStatement(
                    "SELECT pg_try_advisory_lock(hashtextextended(?, 0))")) {
                statement.setString(1, tenantId);
                try (ResultSet result = statement.executeQuery()) {
                    if (!result.next() || !result.getBoolean(1)) {
                        closeAdvisorySession(session, tenantId);
                        throw new ProvisioningException("tenant lifecycle is BUSY for '" + tenantId
                                + "'; another saga owns the session lock");
                    }
                }
            }
            return session;
        } catch (SQLException | RuntimeException failure) {
            if (failure instanceof ProvisioningException pe) throw pe;
            throw new ProvisioningException("could not acquire tenant lifecycle lock for '" + tenantId + "'", failure);
        }
    }

    private void closeAdvisorySession(Connection session, String tenantId) {
        if (session == null) return;
        try {
            if (!session.isClosed()) {
                try (PreparedStatement statement = session.prepareStatement(
                        "SELECT pg_advisory_unlock(hashtextextended(?, 0))")) {
                    statement.setString(1, tenantId);
                    statement.executeQuery().close();
                }
            }
        } catch (SQLException ignored) {
            // Closing the session releases the advisory lock even if the explicit unlock cannot run.
        } finally {
            try {
                session.close();
            } catch (SQLException ignored) {
                // The durable BUSY row remains fail-closed if the session cannot be closed cleanly.
            }
        }
    }

    public static final class Lease implements AutoCloseable {
        private final String tenantId;
        private final String ownerToken;
        private final TenantLifecycleLockStore store;
        private final ScheduledFuture<?> heartbeat;
        private final AtomicBoolean lost;
        private final Connection session;
        private final AtomicBoolean closed = new AtomicBoolean(false);

        private Lease(String tenantId, String ownerToken, TenantLifecycleLockStore store,
                      ScheduledFuture<?> heartbeat, AtomicBoolean lost, Connection session) {
            this.tenantId = tenantId;
            this.ownerToken = ownerToken;
            this.store = store;
            this.heartbeat = heartbeat;
            this.lost = lost;
            this.session = session;
        }

        String tenantId() { return tenantId; }
        String ownerToken() { return ownerToken; }
        ScheduledFuture<?> heartbeat() { return heartbeat; }
        Connection session() { return session; }
        boolean lost() { return lost.get(); }

        /** Test seam: model a lost heartbeat while the session fence remains held. */
        void markLostForTest() { lost.set(true); }

        public void assertOwned() {
            if (lost.get()) {
                throw new ProvisioningException("tenant lifecycle lease was lost for '" + tenantId + "'");
            }
        }

        @Override
        public void close() {
            if (closed.compareAndSet(false, true) && store != null) store.release(this);
        }
    }

    record LockObservation(String ownerKey, Instant leaseUntil) {
        boolean expired() { return leaseUntil.isBefore(Instant.now()); }
    }

    record ReconciliationEvidence(
            String operator,
            String approver,
            String correlationId,
            String evidenceHash,
            String payload,
            boolean directoryVerified,
            boolean runtimeVerified,
            boolean redisVerified,
            boolean auditVerified) {
        private void validate() {
            if (operator == null || operator.isBlank() || approver == null || approver.isBlank()
                    || operator.equals(approver)) {
                throw new ProvisioningException("lifecycle reconciliation requires distinct operator and approver");
            }
            if (correlationId == null || correlationId.isBlank()) {
                throw new ProvisioningException("lifecycle reconciliation correlation is required");
            }
            if (evidenceHash == null || evidenceHash.isBlank() || payload == null || payload.isBlank()) {
                throw new ProvisioningException("lifecycle reconciliation immutable evidence is required");
            }
            if (!directoryVerified || !runtimeVerified || !redisVerified || !auditVerified) {
                throw new ProvisioningException("lifecycle reconciliation requires directory/runtime/Redis/audit proof");
            }
        }
    }
}
