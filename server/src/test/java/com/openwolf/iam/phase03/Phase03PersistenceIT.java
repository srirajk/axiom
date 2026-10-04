package com.openwolf.iam.phase03;

import io.lettuce.core.RedisClient;
import org.flywaydb.core.Flyway;
import org.flywaydb.core.api.MigrationVersion;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.Statement;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Phase 0.3 against localhost forwards to axiom-phase0-test only. No original rollout connection.
 * Each PostgreSQL test creates an exact random database and drops only that database in finally.
 * The Redis test uses a short-lived random key and deletes it in finally.
 */
@EnabledIfEnvironmentVariable(named = "AXIOM_PHASE03_TEST_NS", matches = "axiom-phase0-test")
class Phase03PersistenceIT {
    private static final String JDBC_URL = required("AXIOM_PHASE03_PG_JDBC_URL");
    private static final String USER = required("AXIOM_PHASE03_PG_USER");
    private static final String PASSWORD = required("AXIOM_PHASE03_PG_PASSWORD");
    private static final String REDIS_PORT = required("AXIOM_PHASE03_REDIS_PORT");

    private static String required(String name) {
        String value = System.getenv(name);
        if (value == null || value.isBlank()) {
            throw new IllegalStateException("missing required Phase 0.3 test setting: " + name);
        }
        return value;
    }

    private static String checkedBaseUrl() {
        assertThat(JDBC_URL).matches("jdbc:postgresql://127\\.0\\.0\\.1:[0-9]{2,5}/axiom");
        assertThat(USER).isEqualTo("axiom");
        return JDBC_URL.substring(0, JDBC_URL.lastIndexOf('/') + 1);
    }

    private static String databaseName(String kind) {
        return "p03_" + kind + "_" + UUID.randomUUID().toString().replace("-", "");
    }

    private static void databaseCommand(String sql) throws Exception {
        try (Connection connection = DriverManager.getConnection(JDBC_URL, USER, PASSWORD);
             Statement statement = connection.createStatement()) {
            statement.execute(sql);
        }
    }

    private static void withDatabase(String kind, DatabaseCheck check) throws Exception {
        String name = databaseName(kind);
        checkedBaseUrl();
        databaseCommand("CREATE DATABASE " + name);
        try {
            check.run(checkedBaseUrl() + name);
        } finally {
            // Generated identifiers contain only the fixed prefix and UUID hex, never user input.
            databaseCommand("DROP DATABASE IF EXISTS " + name + " WITH (FORCE)");
        }
    }

    private static Flyway flyway(String url, MigrationVersion target) {
        var config = Flyway.configure().dataSource(url, USER, PASSWORD)
                .locations("classpath:db/migration");
        if (target != null) config.target(target);
        return config.load();
    }

    private static void assertV29Schema(String url) throws Exception {
        try (Connection connection = DriverManager.getConnection(url, USER, PASSWORD);
             Statement statement = connection.createStatement();
             ResultSet rows = statement.executeQuery(
                     "SELECT indexdef FROM pg_indexes WHERE schemaname='public' AND indexname='uq_active_exchange_route'")) {
            assertThat(rows.next()).isTrue();
            assertThat(rows.getString(1)).contains("agent_exchange_routes", "status", "ACTIVE");
            assertThat(rows.next()).isFalse();
        }
    }

    @Test
    void freshMigrationReachesV29OnRealPostgres() throws Exception {
        withDatabase("fresh", url -> {
            Flyway migrations = flyway(url, null);
            migrations.migrate();
            migrations.validate();
            assertThat(migrations.info().current().getVersion().getVersion()).isEqualTo("29");
            assertV29Schema(url);
        });
    }

    @Test
    void supportedV28ToV29UpgradePreservesExistingRows() throws Exception {
        withDatabase("upgrade", url -> {
            Flyway before = flyway(url, MigrationVersion.fromVersion("28"));
            before.migrate();
            assertThat(before.info().current().getVersion().getVersion()).isEqualTo("28");
            try (Connection connection = DriverManager.getConnection(url, USER, PASSWORD);
                 Statement statement = connection.createStatement()) {
                statement.execute("INSERT INTO tenants (id, name, slug) "
                        + "VALUES ('p03-upgrade-tenant', 'Phase 03', 'phase-03')");
            }
            Flyway after = flyway(url, null);
            after.migrate();
            after.validate();
            assertThat(after.info().current().getVersion().getVersion()).isEqualTo("29");
            assertV29Schema(url);
            try (Connection connection = DriverManager.getConnection(url, USER, PASSWORD);
                 Statement statement = connection.createStatement();
                 ResultSet rows = statement.executeQuery(
                         "SELECT count(*) FROM tenants WHERE id='p03-upgrade-tenant'")) {
                assertThat(rows.next()).isTrue();
                assertThat(rows.getInt(1)).isEqualTo(1);
            }
        });
    }

    @Test
    void redisRoundTripUsesOnlyTemporaryKey() {
        int port = Integer.parseInt(REDIS_PORT);
        assertThat(port).isBetween(1024, 65535);
        String key = "phase03:" + UUID.randomUUID();
        RedisClient client = RedisClient.create("redis://127.0.0.1:" + port);
        try (var connection = client.connect()) {
            var redis = connection.sync();
            try {
                assertThat(redis.setex(key, 60, "phase03-ok")).isEqualTo("OK");
                assertThat(redis.get(key)).isEqualTo("phase03-ok");
            } finally {
                redis.del(key);
            }
            assertThat(redis.get(key)).isNull();
        } finally {
            client.shutdown();
        }
    }

    @FunctionalInterface
    private interface DatabaseCheck {
        void run(String url) throws Exception;
    }
}
