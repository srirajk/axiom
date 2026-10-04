package com.openwolf.iam.service;

import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.Statement;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/** PostgreSQL proof of the shared client-row lock used by both registration services. */
@Testcontainers
class BrokerWorkloadRegistrationLockIT {
    @Container
    static final GenericContainer<?> POSTGRES = new GenericContainer<>("postgres:16")
            .withEnv("POSTGRES_DB", "axiom_race_test")
            .withEnv("POSTGRES_USER", "axiom")
            .withEnv("POSTGRES_PASSWORD", "isolated-test-only")
            .withExposedPorts(5432);

    private static final String TENANT = "p11-race-test";

    private static String url() {
        return "jdbc:postgresql://" + POSTGRES.getHost() + ":" + POSTGRES.getMappedPort(5432)
                + "/axiom_race_test";
    }

    private static Connection connection() throws Exception {
        return DriverManager.getConnection(url(), "axiom", "isolated-test-only");
    }

    @BeforeAll
    static void migrateAndSeed() throws Exception {
        Flyway.configure().dataSource(url(), "axiom", "isolated-test-only")
                .locations("classpath:db/migration").load().migrate();
        try (Connection c = connection(); Statement sql = c.createStatement()) {
            sql.execute("INSERT INTO tenants(id,name,slug) VALUES ('" + TENANT
                    + "','Registration race test','p11-race-test')");
            sql.execute("INSERT INTO tenant_applications(id,tenant_id,application_key,display_name,audience,status) "
                    + "VALUES ('00000000-0000-0000-0000-000000000011','" + TENANT
                    + "','race','Race test','race-api','ACTIVE')");
        }
    }

    @Test
    void brokerFirstWorkloadSecondSeesCommittedConflict() throws Exception {
        proveSerializedRegistration(true);
    }

    @Test
    void workloadFirstBrokerSecondSeesCommittedConflict() throws Exception {
        proveSerializedRegistration(false);
    }

    private static void proveSerializedRegistration(boolean brokerFirst) throws Exception {
        String clientId = "race-" + UUID.randomUUID();
        try (Connection c = connection(); Statement sql = c.createStatement()) {
            sql.execute("INSERT INTO oauth2_registered_client(id,client_id,client_name,"
                    + "client_authentication_methods,authorization_grant_types,scopes,client_settings,token_settings) "
                    + "VALUES ('" + clientId + "','" + clientId
                    + "','Race client','client_secret_basic','client_credentials','race:invoke','{}','{}')");
            sql.execute("INSERT INTO tenant_application_clients(id,application_id,client_id,client_type,status) "
                    + "VALUES ('" + UUID.randomUUID()
                    + "','00000000-0000-0000-0000-000000000011','" + clientId
                    + "','CONFIDENTIAL_SERVICE','ACTIVE')");
        }

        CountDownLatch firstLocked = new CountDownLatch(1);
        CountDownLatch releaseFirst = new CountDownLatch(1);
        CountDownLatch secondAttempting = new CountDownLatch(1);
        var executor = Executors.newFixedThreadPool(2);
        try {
            var first = executor.submit(() -> {
                try (Connection c = connection()) {
                    c.setAutoCommit(false);
                    lockClient(c, clientId);
                    firstLocked.countDown();
                    if (!releaseFirst.await(10, TimeUnit.SECONDS)) throw new IllegalStateException("first release timed out");
                    insertIdentity(c, clientId, brokerFirst);
                    c.commit();
                }
                return true;
            });
            assertThat(firstLocked.await(10, TimeUnit.SECONDS)).isTrue();
            var second = executor.submit(() -> {
                try (Connection c = connection()) {
                    c.setAutoCommit(false);
                    secondAttempting.countDown();
                    lockClient(c, clientId);
                    boolean conflict = identityExists(c, clientId, brokerFirst);
                    if (!conflict) insertIdentity(c, clientId, !brokerFirst);
                    c.commit();
                    return conflict;
                }
            });
            assertThat(secondAttempting.await(10, TimeUnit.SECONDS)).isTrue();
            assertThatThrownBy(() -> second.get(150, TimeUnit.MILLISECONDS))
                    .isInstanceOf(TimeoutException.class);
            releaseFirst.countDown();
            assertThat(first.get(10, TimeUnit.SECONDS)).isTrue();
            assertThat(second.get(10, TimeUnit.SECONDS)).isTrue();
            try (Connection c = connection()) {
                assertThat(identityExists(c, clientId, brokerFirst)).isTrue();
                assertThat(identityExists(c, clientId, !brokerFirst)).isFalse();
            }
        } finally {
            releaseFirst.countDown();
            executor.shutdownNow();
        }
    }

    private static void lockClient(Connection c, String clientId) throws Exception {
        try (Statement sql = c.createStatement()) {
            sql.execute("SELECT id FROM tenant_application_clients WHERE client_id='" + clientId + "' FOR UPDATE");
        }
    }

    private static boolean identityExists(Connection c, String clientId, boolean broker) throws Exception {
        String table = broker ? "trusted_exchange_brokers" : "agent_workload_identities";
        try (Statement sql = c.createStatement(); var rows = sql.executeQuery(
                "SELECT 1 FROM " + table + " WHERE tenant_id='" + TENANT
                        + "' AND oauth_client_id='" + clientId + "'")) {
            return rows.next();
        }
    }

    private static void insertIdentity(Connection c, String clientId, boolean broker) throws Exception {
        try (Statement sql = c.createStatement()) {
            if (broker) {
                sql.execute("INSERT INTO trusted_exchange_brokers(id,tenant_id,oauth_client_id,"
                        + "gateway_audience,allowed_scopes,status,created_at) VALUES ('" + UUID.randomUUID()
                        + "','" + TENANT + "','" + clientId + "','gateway-" + clientId
                        + "','[]','ACTIVE',now())");
            } else {
                sql.execute("INSERT INTO agent_workload_identities(id,tenant_id,workload_ref,name,"
                        + "oauth_client_id,status,created_at) VALUES ('" + UUID.randomUUID() + "','"
                        + TENANT + "','agent:" + clientId + "','Race Agent','" + clientId
                        + "','ACTIVE',now())");
            }
        }
    }
}
