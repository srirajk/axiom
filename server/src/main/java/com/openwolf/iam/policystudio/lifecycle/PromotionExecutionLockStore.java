package com.openwolf.iam.policystudio.lifecycle;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Component;

import jakarta.annotation.PreDestroy;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Objects;
import java.util.UUID;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

/** Durable execution fence held across the complete external promotion operation. */
@Component
public class PromotionExecutionLockStore {

    private final JdbcTemplate jdbc;
    private final long leaseSeconds;
    private final ScheduledExecutorService heartbeat;

    @Autowired
    public PromotionExecutionLockStore(
            JdbcTemplate jdbc,
            @Value("${axiom.policystudio.execution-lock-seconds:900}") long leaseSeconds) {
        this.jdbc = jdbc;
        this.leaseSeconds = Math.max(30L, leaseSeconds);
        this.heartbeat = Executors.newSingleThreadScheduledExecutor(runnable -> {
            Thread thread = new Thread(runnable, "axiom-promotion-execution-heartbeat");
            thread.setDaemon(true);
            return thread;
        });
    }

    public Lease acquire(String idempotencyKey) {
        String owner = UUID.randomUUID().toString();
        Connection session = openSession(idempotencyKey);
        try {
            int inserted = jdbc.update("""
                    INSERT INTO promotion_execution_locks (idempotency_key, owner_key, lease_until)
                    VALUES (?, ?, now() + (? * interval '1 second'))
                    ON CONFLICT (idempotency_key) DO NOTHING
                    """, idempotencyKey, owner, leaseSeconds);
            if (inserted != 1) {
                // The dedicated advisory session was acquired before this insert. A conflicting row can
                // therefore only be an abandoned row from a crashed owner (a live owner still holds the
                // same advisory key and openSession would have failed). Clear that durable breadcrumb and
                // replay through the same content-addressed/terminal-CAS promotion path.
                int removed = jdbc.update("DELETE FROM promotion_execution_locks WHERE idempotency_key = ?",
                        idempotencyKey);
                if (removed != 1) {
                    throw new PromotionExecutionBusyException("promotion idempotency key is BUSY");
                }
                inserted = jdbc.update("""
                        INSERT INTO promotion_execution_locks (idempotency_key, owner_key, lease_until)
                        VALUES (?, ?, now() + (? * interval '1 second'))
                        """, idempotencyKey, owner, leaseSeconds);
                if (inserted != 1) {
                    throw new PromotionExecutionBusyException("promotion idempotency key recovery raced");
                }
            }
        } catch (RuntimeException failure) {
            closeSession(session, idempotencyKey);
            throw failure;
        }
        AtomicBoolean lost = new AtomicBoolean(false);
        ScheduledFuture<?> renewal = heartbeat.scheduleAtFixedRate(
                () -> renew(idempotencyKey, owner, lost),
                Math.max(1L, leaseSeconds / 3L), Math.max(1L, leaseSeconds / 3L), TimeUnit.SECONDS);
        return new Lease(idempotencyKey, owner, session, renewal, lost);
    }

    @PreDestroy
    void shutdown() {
        heartbeat.shutdownNow();
    }

    private void renew(String key, String owner, AtomicBoolean lost) {
        if (lost.get()) return;
        try {
            int changed = jdbc.update("""
                    UPDATE promotion_execution_locks
                    SET lease_until = now() + (? * interval '1 second')
                    WHERE idempotency_key = ? AND owner_key = ?
                    """, leaseSeconds, key, owner);
            if (changed != 1) lost.set(true);
        } catch (RuntimeException failure) {
            lost.set(true);
        }
    }

    private Connection openSession(String key) {
        try {
            Connection session = Objects.requireNonNull(jdbc.getDataSource(), "promotion JDBC datasource")
                    .getConnection();
            try (PreparedStatement statement = session.prepareStatement(
                    "SELECT pg_try_advisory_lock(hashtextextended(?, 3))")) {
                statement.setString(1, key);
                try (ResultSet result = statement.executeQuery()) {
                    if (!result.next() || !result.getBoolean(1)) {
                        closeSession(session, key);
                        throw new PromotionExecutionBusyException("promotion idempotency key is BUSY");
                    }
                }
            }
            return session;
        } catch (SQLException | RuntimeException failure) {
            if (failure instanceof PromotionExecutionBusyException busy) throw busy;
            throw new PromotionExecutionBusyException("could not acquire promotion execution fence", failure);
        }
    }

    private void release(Lease lease) {
        lease.renewal.cancel(false);
        if (!lease.lost.get()) {
            jdbc.update("DELETE FROM promotion_execution_locks WHERE idempotency_key = ? AND owner_key = ?",
                    lease.key, lease.owner);
        }
        closeSession(lease.session, lease.key);
    }

    private void closeSession(Connection session, String key) {
        if (session == null) return;
        try {
            if (!session.isClosed()) {
                try (PreparedStatement statement = session.prepareStatement(
                        "SELECT pg_advisory_unlock(hashtextextended(?, 3))")) {
                    statement.setString(1, key);
                    statement.executeQuery().close();
                }
            }
        } catch (SQLException ignored) {
            // Closing the session releases the advisory fence; a durable row remains fail-closed.
        } finally {
            try { session.close(); } catch (SQLException ignored) { }
        }
    }

    public final class Lease implements AutoCloseable {
        private final String key;
        private final String owner;
        private final Connection session;
        private final ScheduledFuture<?> renewal;
        private final AtomicBoolean lost;
        private final AtomicBoolean closed = new AtomicBoolean(false);

        private Lease(String key, String owner, Connection session,
                      ScheduledFuture<?> renewal, AtomicBoolean lost) {
            this.key = key;
            this.owner = owner;
            this.session = session;
            this.renewal = renewal;
            this.lost = lost;
        }

        public void assertOwned() {
            if (lost.get()) throw new PromotionExecutionBusyException("promotion execution fence was lost");
            try {
                if (session == null || session.isClosed()) {
                    lost.set(true);
                    throw new PromotionExecutionBusyException("promotion execution session was closed");
                }
                Integer ownerRow = jdbc.queryForObject("""
                        SELECT count(*) FROM promotion_execution_locks
                        WHERE idempotency_key = ? AND owner_key = ?
                        """, Integer.class, key, owner);
                if (ownerRow == null || ownerRow != 1) {
                    lost.set(true);
                    throw new PromotionExecutionBusyException(
                            "promotion execution fence ownership changed before commit");
                }
            } catch (SQLException failure) {
                lost.set(true);
                throw new PromotionExecutionBusyException("could not verify promotion execution fence", failure);
            } catch (RuntimeException failure) {
                lost.set(true);
                throw failure;
            }
        }

        /** Test seam for a crashed/uncertain owner before its scheduled heartbeat runs. */
        void markLostForTest() {
            lost.set(true);
        }

        @Override
        public void close() {
            if (closed.compareAndSet(false, true)) release(this);
        }
    }
}
