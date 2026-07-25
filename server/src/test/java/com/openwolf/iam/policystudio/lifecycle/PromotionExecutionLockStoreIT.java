package com.openwolf.iam.policystudio.lifecycle;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.DockerImageName;

import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/** Real-Postgres proof for the promotion execution fence and crash-safe replay. */
@Testcontainers
class PromotionExecutionLockStoreIT {

    @Container
    static final GenericContainer<?> POSTGRES = new GenericContainer<>(DockerImageName.parse(
            "postgres:16@sha256:33f923b05f64ca54ac4401c01126a6b92afe839a0aa0a52bc5aeb5cc958e5f20"))
            .withEnv("POSTGRES_USER", "axiom")
            .withEnv("POSTGRES_PASSWORD", "axiom")
            .withEnv("POSTGRES_DB", "axiom")
            .withExposedPorts(5432)
            .waitingFor(Wait.forListeningPort());

    @BeforeEach
    void resetSchema() {
        JdbcTemplate jdbc = jdbc();
        jdbc.execute("""
                CREATE TABLE IF NOT EXISTS promotion_execution_locks (
                    idempotency_key TEXT PRIMARY KEY, owner_key TEXT NOT NULL, lease_until TIMESTAMPTZ NOT NULL
                )
                """);
        jdbc.update("DELETE FROM promotion_execution_locks");
    }

    @Test
    void rowOwnerChangeIsDetectedBeforeHeartbeat() {
        JdbcTemplate jdbc = jdbc();
        PromotionExecutionLockStore store = new PromotionExecutionLockStore(jdbc, 30);
        PromotionExecutionLockStore.Lease lease = store.acquire("promotion-a");
        try {
            jdbc.update("UPDATE promotion_execution_locks SET owner_key = ? WHERE idempotency_key = ?",
                    "replacement-owner", "promotion-a");
            assertThatThrownBy(lease::assertOwned)
                    .isInstanceOf(PromotionExecutionBusyException.class)
                    .hasMessageContaining("ownership changed");
            assertThat(jdbc.queryForObject("SELECT owner_key FROM promotion_execution_locks "
                    + "WHERE idempotency_key = ?", String.class, "promotion-a"))
                    .isEqualTo("replacement-owner");
        } finally {
            lease.close();
            jdbc.update("DELETE FROM promotion_execution_locks WHERE idempotency_key = ?", "promotion-a");
            store.shutdown();
        }
    }

    @Test
    void crashedSessionLeavesRowButNextOwnerCanSafelyReplay() {
        JdbcTemplate firstJdbc = jdbc();
        JdbcTemplate secondJdbc = jdbc();
        PromotionExecutionLockStore first = new PromotionExecutionLockStore(firstJdbc, 30);
        PromotionExecutionLockStore second = new PromotionExecutionLockStore(secondJdbc, 30);
        PromotionExecutionLockStore.Lease crashed = first.acquire("promotion-b");
        crashed.markLostForTest();
        crashed.close();
        try {
            PromotionExecutionLockStore.Lease replay = second.acquire("promotion-b");
            try {
                replay.assertOwned();
                assertThat(secondJdbc.queryForObject("SELECT count(*) FROM promotion_execution_locks "
                        + "WHERE idempotency_key = ?", Integer.class, "promotion-b")).isEqualTo(1);
            } finally {
                replay.close();
            }
        } finally {
            secondJdbc.update("DELETE FROM promotion_execution_locks WHERE idempotency_key = ?", "promotion-b");
            first.shutdown();
            second.shutdown();
        }
    }

    private static JdbcTemplate jdbc() {
        while (!POSTGRES.isRunning()) {
            try {
                TimeUnit.MILLISECONDS.sleep(10);
            } catch (InterruptedException interrupted) {
                Thread.currentThread().interrupt();
                throw new IllegalStateException("interrupted while waiting for Postgres", interrupted);
            }
        }
        return new JdbcTemplate(new DriverManagerDataSource(
                "jdbc:postgresql://" + POSTGRES.getHost() + ":" + POSTGRES.getMappedPort(5432) + "/axiom",
                "axiom", "axiom"));
    }
}
