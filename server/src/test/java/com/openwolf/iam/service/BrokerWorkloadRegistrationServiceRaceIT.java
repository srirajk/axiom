package com.openwolf.iam.service;

import com.openwolf.iam.IamApplication;
import com.openwolf.iam.dto.AgentExchangeContracts.RegisterTrustedBrokerRequest;
import com.openwolf.iam.exception.ResourceConflictException;
import com.openwolf.iam.tenancy.ActiveTenantDirectory;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.DockerImageName;

import javax.sql.DataSource;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.Callable;
import java.util.concurrent.CyclicBarrier;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.fail;

/**
 * G-02 full-service race on disposable PostgreSQL and Redis containers.
 *
 * <p>The production {@link AgentExchangeAuthorityService#registerBroker} and
 * {@link CiamDelegationService#registerWorkload} beans race for the same confidential client. Each order is forced
 * deterministically: the test holds the shared client row lock, queues the first and then the second service call
 * behind it, proves through {@code pg_stat_activity} that both are blocked on that lock, and then releases it.
 * PostgreSQL grants the queued row lock in arrival order, so the first call commits and the second must observe the
 * committed identity and fail with a conflict. An additional unforced race repeats simultaneous starts.
 *
 * <p>Isolation: containers are created by Testcontainers for this class only (random host ports, removed after the
 * class by Testcontainers/Ryuk); all secrets are generated per run; no external system is contacted.
 */
@Testcontainers
@SpringBootTest(classes = IamApplication.class, webEnvironment = SpringBootTest.WebEnvironment.NONE)
class BrokerWorkloadRegistrationServiceRaceIT {

    private static final String TENANT = "g02-race-test";
    private static final String SCOPE = "race:invoke";
    private static final String CONFLICT = "trusted Gateway broker cannot be an Agent workload";
    private static final Path KEY_DIR = tempDir();

    @Container
    static final GenericContainer<?> POSTGRES = new GenericContainer<>(DockerImageName.parse("postgres:16"))
            .withEnv("POSTGRES_USER", "axiom")
            .withEnv("POSTGRES_PASSWORD", "g02-isolated-test-only")
            .withEnv("POSTGRES_DB", "axiom_g02_race")
            .withExposedPorts(5432)
            .waitingFor(Wait.forLogMessage(".*database system is ready to accept connections.*", 2));

    @Container
    static final GenericContainer<?> REDIS = new GenericContainer<>(DockerImageName.parse("redis:7-alpine"))
            .withExposedPorts(6379)
            .waitingFor(Wait.forListeningPort());

    @DynamicPropertySource
    static void properties(DynamicPropertyRegistry registry) {
        registry.add("spring.datasource.url", () -> "jdbc:postgresql://" + POSTGRES.getHost() + ":"
                + POSTGRES.getMappedPort(5432) + "/axiom_g02_race");
        registry.add("spring.datasource.username", () -> "axiom");
        registry.add("spring.datasource.password", () -> "g02-isolated-test-only");
        registry.add("spring.datasource.hikari.maximum-pool-size", () -> "10");
        registry.add("spring.data.redis.host", REDIS::getHost);
        registry.add("spring.data.redis.port", () -> REDIS.getMappedPort(6379));
        registry.add("iam.cerbos.authz-enabled", () -> "false");
        registry.add("iam.signing-key-path", () -> KEY_DIR.resolve("signing-key.json").toString());
        registry.add("iam.signing-key-allow-generation", () -> "true");
        registry.add("iam.secrets.master-key", BrokerWorkloadRegistrationServiceRaceIT::randomMasterKey);
        registry.add("axiom.bootstrap.enabled", () -> "false");
        registry.add("iam.oauth2.approved-business-scopes", () -> SCOPE);
        registry.add("iam.policy-studio.base-bundle-dir",
                () -> Path.of("..", "platform-policy", "policies").toAbsolutePath().normalize().toString());
    }

    @Autowired AgentExchangeAuthorityService exchangeAuthority;
    @Autowired CiamDelegationService delegation;
    @Autowired ActiveTenantDirectory directory;
    @Autowired JdbcTemplate jdbc;
    @Autowired DataSource dataSource;

    private static boolean tenantSeeded;

    @BeforeEach
    void seedTenantOnce() {
        if (tenantSeeded) return;
        jdbc.update("INSERT INTO tenants (id, name, slug) VALUES (?, 'G-02 race test', ?)", TENANT, TENANT);
        directory.activate(TENANT, "g02-race-test");
        tenantSeeded = true;
    }

    @AfterAll
    static void removeTemporaryKeyMaterial() throws Exception {
        try (var files = Files.walk(KEY_DIR)) {
            files.sorted((a, b) -> b.getNameCount() - a.getNameCount()).forEach(p -> p.toFile().delete());
        }
    }

    // -----------------------------------------------------------------------------------------------------------------
    // Forced orders
    // -----------------------------------------------------------------------------------------------------------------

    @Test
    void brokerQueuedFirstWinsAndWorkloadQueuedSecondIsRejected() throws Exception {
        Fixture f = seedClient();
        Outcome outcome = forcedRace(f, true);
        assertThat(outcome.firstError()).as("broker (queued first) must succeed").isNull();
        assertConflict(outcome.secondError(), "workload (queued second)");
        assertIdentityCounts(f, 1, 0);
    }

    @Test
    void workloadQueuedFirstWinsAndBrokerQueuedSecondIsRejected() throws Exception {
        Fixture f = seedClient();
        Outcome outcome = forcedRace(f, false);
        assertThat(outcome.firstError()).as("workload (queued first) must succeed").isNull();
        assertConflict(outcome.secondError(), "broker (queued second)");
        assertIdentityCounts(f, 0, 1);
    }

    // -----------------------------------------------------------------------------------------------------------------
    // Unforced simultaneous starts (both submission orders), exactly one identity each time
    // -----------------------------------------------------------------------------------------------------------------

    @Test
    void simultaneousStartsAlwaysLeaveExactlyOneIdentity() throws Exception {
        ExecutorService pool = Executors.newFixedThreadPool(2);
        try {
            for (int i = 0; i < 20; i++) {
                Fixture f = seedClient();
                CyclicBarrier start = new CyclicBarrier(2);
                boolean brokerSubmittedFirst = i % 2 == 0;
                Callable<Void> broker = () -> { start.await(10, TimeUnit.SECONDS); registerBroker(f); return null; };
                Callable<Void> workload = () -> { start.await(10, TimeUnit.SECONDS); registerWorkload(f); return null; };
                Future<Void> a = pool.submit(brokerSubmittedFirst ? broker : workload);
                Future<Void> b = pool.submit(brokerSubmittedFirst ? workload : broker);
                Throwable ea = errorOf(a);
                Throwable eb = errorOf(b);
                int successes = (ea == null ? 1 : 0) + (eb == null ? 1 : 0);
                assertThat(successes).as("iteration %d: exactly one registration succeeds", i).isEqualTo(1);
                assertConflict(ea != null ? ea : eb, "iteration " + i + " loser");
                int brokers = count("trusted_exchange_brokers", f.clientId());
                int workloads = count("agent_workload_identities", f.clientId());
                assertThat(brokers + workloads).as("iteration %d: exactly one identity row", i).isEqualTo(1);
            }
        } finally {
            pool.shutdownNow();
        }
    }

    // -----------------------------------------------------------------------------------------------------------------
    // Mechanics
    // -----------------------------------------------------------------------------------------------------------------

    private record Fixture(String clientId, String audience) {}

    private record Outcome(Throwable firstError, Throwable secondError) {}

    /** Hold the client row lock, queue first then second behind it, prove both wait, release, collect. */
    private Outcome forcedRace(Fixture f, boolean brokerFirst) throws Exception {
        ExecutorService pool = Executors.newFixedThreadPool(2);
        try (Connection holder = dataSource.getConnection()) {
            holder.setAutoCommit(false);
            int holderPid = backendPid(holder);
            try (PreparedStatement lock = holder.prepareStatement(
                    "SELECT id FROM tenant_application_clients WHERE client_id = ? FOR UPDATE")) {
                lock.setString(1, f.clientId());
                try (ResultSet rows = lock.executeQuery()) {
                    assertThat(rows.next()).as("seeded client row exists").isTrue();
                }
            }
            Callable<Void> broker = () -> { registerBroker(f); return null; };
            Callable<Void> workload = () -> { registerWorkload(f); return null; };

            Future<Void> first = pool.submit(brokerFirst ? broker : workload);
            awaitWaiters(holderPid, 1);
            Future<Void> second = pool.submit(brokerFirst ? workload : broker);
            awaitWaiters(holderPid, 2);
            assertThat(first.isDone()).as("first call is blocked on the shared client lock").isFalse();
            assertThat(second.isDone()).as("second call is blocked on the shared client lock").isFalse();
            assertIdentityCounts(f, 0, 0);

            holder.rollback();   // release the lock; PostgreSQL hands it to the first queued waiter
            return new Outcome(errorOf(first), errorOf(second));
        } finally {
            pool.shutdownNow();
        }
    }

    /** Wait until exactly {@code expected} other backends are blocked on a lock while locking the client row. */
    private void awaitWaiters(int holderPid, int expected) throws InterruptedException {
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(15);
        int seen = -1;
        while (System.nanoTime() < deadline) {
            // Lock clause is not matched textually: Hibernate 6 issues PESSIMISTIC_WRITE on PostgreSQL as
            // "for no key update", which conflicts with the holder's FOR UPDATE.
            seen = jdbc.queryForObject("""
                    SELECT count(*) FROM pg_stat_activity
                    WHERE datname = current_database() AND pid <> ? AND pid <> pg_backend_pid()
                      AND wait_event_type = 'Lock' AND query ILIKE '%tenant_application_clients%'
                    """, Integer.class, holderPid);
            if (seen == expected) return;
            Thread.sleep(20);
        }
        List<String> activity = jdbc.queryForList("""
                SELECT coalesce(wait_event_type, '-') || '/' || coalesce(wait_event, '-') || ' ' || state || ' '
                       || left(regexp_replace(query, '\\s+', ' ', 'g'), 160)
                FROM pg_stat_activity WHERE datname = current_database() AND pid <> pg_backend_pid()
                """, String.class);
        fail("expected %d registration call(s) blocked on the client row lock, saw %d; activity=%s",
                expected, seen, activity);
    }

    private Fixture seedClient() {
        String suffix = UUID.randomUUID().toString().substring(0, 12);
        String clientId = "g02-" + suffix;
        String audience = "g02-gateway-" + suffix;
        UUID appId = UUID.randomUUID();
        jdbc.update("INSERT INTO tenant_applications (id, tenant_id, application_key, display_name, audience, status) "
                + "VALUES (?, ?, ?, 'G-02 race', ?, 'ACTIVE')", appId, TENANT, "g02-" + suffix, audience);
        jdbc.update("INSERT INTO oauth2_registered_client (id, client_id, client_name, client_authentication_methods, "
                + "authorization_grant_types, scopes, client_settings, token_settings) "
                + "VALUES (?, ?, 'G-02 race', 'client_secret_basic', 'client_credentials', ?, '{}', '{}')",
                clientId, clientId, SCOPE);
        jdbc.update("INSERT INTO tenant_application_clients (id, application_id, client_id, client_type, status, "
                + "allowed_scopes) VALUES (?, ?, ?, 'CONFIDENTIAL_SERVICE', 'ACTIVE', ?::jsonb)",
                UUID.randomUUID(), appId, clientId, "[\"" + SCOPE + "\"]");
        return new Fixture(clientId, audience);
    }

    private void registerBroker(Fixture f) {
        exchangeAuthority.registerBroker(TENANT, new RegisterTrustedBrokerRequest(f.clientId(), f.audience(),
                Set.of(SCOPE)), "g02-race-test", "g02-" + UUID.randomUUID());
    }

    private void registerWorkload(Fixture f) {
        delegation.registerWorkload(TENANT, "agent:" + f.clientId() + ":test", "G-02 race Agent", f.clientId(),
                "g02-race-test", "g02-" + UUID.randomUUID());
    }

    private static Throwable errorOf(Future<Void> future) throws InterruptedException {
        try {
            future.get(20, TimeUnit.SECONDS);
            return null;
        } catch (ExecutionException e) {
            return e.getCause();
        } catch (java.util.concurrent.TimeoutException e) {
            fail("registration call did not finish within 20s");
            return null;
        }
    }

    private static void assertConflict(Throwable error, String who) {
        assertThat(error).as("%s must be rejected", who).isNotNull();
        assertThat(error).as("%s must fail with the broker/workload exclusivity conflict", who)
                .isInstanceOf(ResourceConflictException.class)
                .hasMessage(CONFLICT);
    }

    private void assertIdentityCounts(Fixture f, int brokers, int workloads) {
        assertThat(count("trusted_exchange_brokers", f.clientId())).as("broker rows").isEqualTo(brokers);
        assertThat(count("agent_workload_identities", f.clientId())).as("workload rows").isEqualTo(workloads);
    }

    private int count(String table, String clientId) {
        List<String> allowed = new ArrayList<>(List.of("trusted_exchange_brokers", "agent_workload_identities"));
        if (!allowed.contains(table)) throw new IllegalArgumentException(table);
        Integer n = jdbc.queryForObject("SELECT count(*) FROM " + table + " WHERE tenant_id = ? AND oauth_client_id = ?",
                Integer.class, TENANT, clientId);
        return n == null ? 0 : n;
    }

    private static int backendPid(Connection connection) throws Exception {
        try (PreparedStatement pid = connection.prepareStatement("SELECT pg_backend_pid()");
             ResultSet rows = pid.executeQuery()) {
            rows.next();
            return rows.getInt(1);
        }
    }

    private static String randomMasterKey() {
        byte[] key = new byte[32];
        new SecureRandom().nextBytes(key);
        return Base64.getEncoder().encodeToString(key);
    }

    private static Path tempDir() {
        try {
            return Files.createTempDirectory("g02-race-keys");
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }
}
