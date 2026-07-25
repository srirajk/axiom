package com.openwolf.iam.tenancy;

import com.openwolf.iam.IamApplication;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.context.annotation.Primary;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.DockerImageName;
import org.springframework.jdbc.core.JdbcTemplate;

import java.nio.file.Path;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * AXM-107 real-PG saga boundary. Two ledger objects use the same repository through separate
 * transactions/connections; a held lease represents the first caller blocked in external staging.
 */
@Testcontainers
@SpringBootTest(classes = IamApplication.class, webEnvironment = SpringBootTest.WebEnvironment.NONE)
@Import(ProvisioningSagaConcurrencyIT.ConcurrencyLedgerConfiguration.class)
class ProvisioningSagaConcurrencyIT {

    @Container
    static final GenericContainer<?> POSTGRES = new GenericContainer<>(DockerImageName.parse(
            "postgres:16@sha256:33f923b05f64ca54ac4401c01126a6b92afe839a0aa0a52bc5aeb5cc958e5f20"))
            .withEnv("POSTGRES_USER", "axiom")
            .withEnv("POSTGRES_PASSWORD", "axiom")
            .withEnv("POSTGRES_DB", "axiom")
            .withExposedPorts(5432)
            .waitingFor(Wait.forListeningPort());

    @Container
    static final GenericContainer<?> REDIS = new GenericContainer<>(DockerImageName.parse(
            "redis:7-alpine@sha256:6ab0b6e7381779332f97b8ca76193e45b0756f38d4c0dcda72dbb3c32061ab99"))
            .withExposedPorts(6379)
            .waitingFor(Wait.forListeningPort());

    @DynamicPropertySource
    static void properties(DynamicPropertyRegistry registry) {
        registry.add("spring.datasource.url", () -> jdbcUrl());
        registry.add("spring.datasource.username", () -> "axiom");
        registry.add("spring.datasource.password", () -> "axiom");
        registry.add("spring.data.redis.host", REDIS::getHost);
        registry.add("spring.data.redis.port", () -> REDIS.getMappedPort(6379));
        registry.add("spring.data.redis.database", () -> "7");
        registry.add("iam.cerbos.authz-enabled", () -> "false");
        registry.add("iam.signing-key-path", () -> signingKeyPath());
        registry.add("iam.signing-key-allow-generation", () -> "true");
        registry.add("iam.oauth2.probata-api.client-secret", () -> "test-client-secret");
        registry.add("axiom.iam.service-tenants.probata-api", () -> "tenant-a");
        registry.add("axiom.bootstrap.enabled", () -> "false");
        registry.add("iam.policy-studio.base-bundle-dir", () -> "../axiom-platform-policy/policies");
    }

    @Autowired ProvisioningOperationRepository operations;
    @Autowired ActiveTenantDirectory directory;
    @Autowired TenantLifecycleLockStore lifecycleLocks;
    @Autowired JdbcTemplate jdbc;
    @Autowired @Qualifier("firstLedger") ProvisioningLedger firstLedger;
    @Autowired @Qualifier("secondLedger") ProvisioningLedger secondLedger;

    @BeforeEach
    void cleanLedger() {
        operations.deleteAllInBatch();
        jdbc.update("DELETE FROM tenant_lifecycle_locks");
    }

    @Test
    void sameKeyHasOneRowAndLaterRetryReconciles() throws Exception {
        assertThat(org.springframework.aop.support.AopUtils.isAopProxy(firstLedger)).isTrue();
        assertThat(org.springframework.aop.support.AopUtils.isAopProxy(secondLedger)).isTrue();
        ProvisioningLedger.ProvisioningLease firstLease = startProvision(firstLedger, "same-key", "tenant-a");
        String ownerBeforeCompetition = assertCommittedLease("tenant-a");
        CountDownLatch externalEntered = new CountDownLatch(1);
        CountDownLatch releaseExternal = new CountDownLatch(1);
        var executor = Executors.newFixedThreadPool(2);
        try {
            Future<?> externalStage = executor.submit(() -> {
                firstLease.assertOwned();
                externalEntered.countDown();
                try {
                    releaseExternal.await(5, TimeUnit.SECONDS);
                } catch (InterruptedException interrupted) {
                    Thread.currentThread().interrupt();
                }
            });
            assertThat(externalEntered.await(5, TimeUnit.SECONDS)).isTrue();
            Future<?> competing = executor.submit(() -> assertThatThrownBy(
                    () -> startProvision(secondLedger, "same-key", "tenant-a"))
                    .isInstanceOf(ProvisioningException.class));
            competing.get(5, TimeUnit.SECONDS);
            assertThat(operations.count()).isEqualTo(1);
            assertThat(assertCommittedLease("tenant-a")).isEqualTo(ownerBeforeCompetition);
            releaseExternal.countDown();
            externalStage.get(5, TimeUnit.SECONDS);
        } finally {
            releaseExternal.countDown();
            executor.shutdownNow();
        }

        firstLease.lease().close();
        ProvisioningLedger.ProvisioningLease retry = startProvision(secondLedger, "same-key", "tenant-a");
        assertThat(retry.operation().getId()).isEqualTo(firstLease.operation().getId());
        retry.lease().close();
        assertThat(operations.count()).isEqualTo(1);
    }

    @Test
    void differentKeysForSameTenantAreExcluded() {
        ProvisioningLedger.ProvisioningLease first = startProvision(firstLedger, "key-one", "tenant-a");
        String ownerBeforeCompetition = assertCommittedLease("tenant-a");
        assertThatThrownBy(() -> startProvision(secondLedger, "key-two", "tenant-a"))
                .isInstanceOf(ProvisioningException.class);
        assertThat(assertCommittedLease("tenant-a")).isEqualTo(ownerBeforeCompetition);
        first.lease().close();
        assertThat(operations.count()).isEqualTo(1);
    }

    @Test
    void provisionAndDeprovisionForSameTenantAreExcluded() {
        ProvisioningLedger.ProvisioningLease first = startProvision(firstLedger, "provision-key", "tenant-a");
        String ownerBeforeCompetition = assertCommittedLease("tenant-a");
        assertThatThrownBy(() -> startDeprovision(secondLedger, "deprovision-key", "tenant-a"))
                .isInstanceOf(ProvisioningException.class);
        assertThat(assertCommittedLease("tenant-a")).isEqualTo(ownerBeforeCompetition);
        first.lease().close();
        assertThat(operations.count()).isEqualTo(1);
    }

    private ProvisioningLedger.ProvisioningLease startProvision(ProvisioningLedger ledger,
                                                                 String key, String tenant) {
        return ledger.startOrResumeProvision(key, new ProvisioningRequest(tenant, "Tenant A", "tenant-a"));
    }

    private ProvisioningLedger.ProvisioningLease startDeprovision(ProvisioningLedger ledger,
                                                                   String key, String tenant) {
        return ledger.startOrResumeDeprovision(key, tenant);
    }

    private String assertCommittedLease(String tenantId) {
        var row = jdbc.queryForMap(
                "SELECT owner_key, lease_until, lease_until > now() AS live FROM tenant_lifecycle_locks WHERE tenant_id = ?",
                tenantId);
        assertThat(row.get("owner_key")).isInstanceOf(String.class);
        assertThat(row.get("lease_until")).isNotNull();
        assertThat(row.get("live")).isEqualTo(true);
        return (String) row.get("owner_key");
    }

    @TestConfiguration(proxyBeanMethods = false)
    static class ConcurrencyLedgerConfiguration {
        @Bean("firstLedger")
        @Primary
        ProvisioningLedger firstLedger(ProvisioningOperationRepository operations,
                                       ActiveTenantDirectory directory,
                                       TenantLifecycleLockStore locks,
                                       ProvisioningLedgerTransactions transactions) {
            return new ProvisioningLedger(operations, directory, locks, transactions);
        }

        @Bean("secondLedger")
        ProvisioningLedger secondLedger(ProvisioningOperationRepository operations,
                                        ActiveTenantDirectory directory,
                                        TenantLifecycleLockStore locks,
                                        ProvisioningLedgerTransactions transactions) {
            return new ProvisioningLedger(operations, directory, locks, transactions);
        }
    }

    private static String jdbcUrl() {
        return "jdbc:postgresql://" + POSTGRES.getHost() + ":" + POSTGRES.getMappedPort(5432) + "/axiom";
    }

    private static String signingKeyPath() {
        return Path.of(System.getProperty("java.io.tmpdir"), "axiom-saga-it-signing-key.json").toString();
    }
}
