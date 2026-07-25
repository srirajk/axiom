package com.openwolf.iam.tenancy;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.BeforeEach;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.DockerImageName;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DriverManagerDataSource;

import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Real-Postgres proof that lifecycle exclusion survives the short ledger transaction and spans the
 * external saga. The two stores deliberately use independent JDBC connections.
 */
@Testcontainers
class TenantLifecycleLockStoreIT {

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
                CREATE TABLE IF NOT EXISTS tenant_lifecycle_locks (
                    tenant_id TEXT PRIMARY KEY, owner_key TEXT NOT NULL, lease_until TIMESTAMPTZ NOT NULL
                )
                """);
        jdbc.update("DELETE FROM tenant_lifecycle_locks");
    }

    @Test
    void sameKeyAttemptCannotEnterExternalStepUntilFirstSagaReleasesLease() throws Exception {
        JdbcTemplate firstJdbc = jdbc();
        TenantLifecycleLockStore first = new TenantLifecycleLockStore(firstJdbc, 30);
        TenantLifecycleLockStore second = new TenantLifecycleLockStore(jdbc(), 30);
        TenantLifecycleLockStore.Lease firstLease = first.acquire("tenant-a");
        CountDownLatch firstExternalStep = new CountDownLatch(1);
        AtomicBoolean secondEnteredExternalStep = new AtomicBoolean(false);
        var executor = Executors.newSingleThreadExecutor();
        try {
            var secondAttempt = executor.submit(() -> {
                try {
                    TenantLifecycleLockStore.Lease lease = second.acquire("tenant-a");
                    secondEnteredExternalStep.set(true);
                    lease.close();
                } finally {
                    firstExternalStep.countDown();
                }
            });
            assertThat(firstExternalStep.await(2, TimeUnit.SECONDS)).isTrue();
            assertThat(secondEnteredExternalStep).as("a competing saga must not enter external work").isFalse();
            assertThatThrownBy(secondAttempt::get).hasCauseInstanceOf(ProvisioningException.class);
        } finally {
            firstLease.close();
            executor.shutdownNow();
            second.shutdown();
            first.shutdown();
        }
    }

    @Test
    void differentTenantsMayProceedAndProvisionDeprovisionShareTheSameExclusion() {
        TenantLifecycleLockStore first = new TenantLifecycleLockStore(jdbc(), 30);
        TenantLifecycleLockStore second = new TenantLifecycleLockStore(jdbc(), 30);
        TenantLifecycleLockStore.Lease tenantA = first.acquire("tenant-a");
        TenantLifecycleLockStore.Lease tenantB = second.acquire("tenant-b");
        assertThatThrownBy(() -> second.acquire("tenant-a"))
                .isInstanceOf(ProvisioningException.class);
        tenantB.close();
        tenantA.close();
        second.shutdown();
        first.shutdown();
    }

    @Test
    void lostHeartbeatCannotPermitExpiryTakeoverOrDuplicateExternalOwnership() {
        JdbcTemplate firstJdbc = jdbc();
        JdbcTemplate secondJdbc = jdbc();
        TenantLifecycleLockStore first = new TenantLifecycleLockStore(firstJdbc, 30);
        TenantLifecycleLockStore second = new TenantLifecycleLockStore(secondJdbc, 30);
        TenantLifecycleLockStore.Lease firstLease = first.acquire("tenant-a");
        String owner = firstJdbc.queryForObject(
                "SELECT owner_key FROM tenant_lifecycle_locks WHERE tenant_id = ?", String.class, "tenant-a");
        firstLease.markLostForTest();
        firstJdbc.update("UPDATE tenant_lifecycle_locks SET lease_until = now() - interval '1 second' "
                + "WHERE tenant_id = ?", "tenant-a");

        assertThatThrownBy(firstLease::assertOwned).isInstanceOf(ProvisioningException.class);
        assertThatThrownBy(() -> second.acquire("tenant-a"))
                .as("a fenced but failed caller must retain durable BUSY ownership")
                .isInstanceOf(ProvisioningException.class);
        assertThat(firstJdbc.queryForObject(
                "SELECT owner_key FROM tenant_lifecycle_locks WHERE tenant_id = ?", String.class, "tenant-a"))
                .isEqualTo(owner);

        firstLease.close();
        assertThatThrownBy(() -> second.acquire("tenant-a"))
                .as("ordinary close after uncertain ownership must not clear the durable BUSY row")
                .isInstanceOf(ProvisioningException.class);
        // The production reconciliation path performs this clear only after two-person artifact checks
        // and an atomic audit record; this explicit test cleanup models that operator action.
        firstJdbc.update("DELETE FROM tenant_lifecycle_locks WHERE tenant_id = ? AND owner_key = ?",
                "tenant-a", owner);
        TenantLifecycleLockStore.Lease recovered = second.acquire("tenant-a");
        recovered.close();
        second.shutdown();
        first.shutdown();
    }

    private static JdbcTemplate jdbc() {
        DriverManagerDataSource dataSource = new DriverManagerDataSource(
                "jdbc:postgresql://" + POSTGRES.getHost() + ":" + POSTGRES.getMappedPort(5432) + "/axiom",
                "axiom", "axiom");
        return new JdbcTemplate(dataSource);
    }
}
