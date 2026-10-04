package com.openwolf.iam.service;

import com.openwolf.iam.IamApplication;
import com.openwolf.iam.auth.SessionTokenValidator;
import com.openwolf.iam.dto.UpdateUserRequest;
import com.openwolf.iam.tenancy.ActiveTenantDirectory;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.DockerImageName;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.CyclicBarrier;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.fail;

/**
 * G-13 race proof: workforce session issuance versus user disable/re-enable, on disposable PostgreSQL and Redis
 * containers, against the production {@link UserService}, {@link IamSessionService} and {@link SessionTokenValidator}.
 *
 * <p>Invariant under test: workforce issuance ({@link IamSessionService#issueForWorkforce}) and active-state changes
 * ({@link UserService#updateUser}) serialize on the principal row lock. Therefore a session is either committed before
 * the disable takes the lock (and the disable revokes it) or the issuance runs after the disable commits (and is
 * refused). No workforce session can be issued across a disable, and none can validate again after re-enable.
 *
 * <p>Each interleaving is forced deterministically: one side runs inside a test-managed outer transaction so it holds
 * the principal row lock; the other side is shown to be blocked on that lock in {@code pg_stat_activity} before the
 * holder commits. An unforced concurrent loop adds repetition.
 *
 * <p>Isolation: Testcontainers creates the containers for this class only (random localhost ports; removed after the
 * class by Testcontainers/Ryuk); secrets are generated per run; nothing external is contacted.
 */
@Testcontainers
@SpringBootTest(classes = IamApplication.class, webEnvironment = SpringBootTest.WebEnvironment.NONE)
class UserDisableSessionRaceIT {

    private static final String TENANT = "g13-race-test";
    private static final Path KEY_DIR = tempDir();

    @Container
    static final GenericContainer<?> POSTGRES = new GenericContainer<>(DockerImageName.parse("postgres:16"))
            .withEnv("POSTGRES_USER", "axiom")
            .withEnv("POSTGRES_PASSWORD", "g13-isolated-test-only")
            .withEnv("POSTGRES_DB", "axiom_g13_race")
            .withExposedPorts(5432)
            .waitingFor(Wait.forLogMessage(".*database system is ready to accept connections.*", 2));

    @Container
    static final GenericContainer<?> REDIS = new GenericContainer<>(DockerImageName.parse("redis:7-alpine"))
            .withExposedPorts(6379)
            .waitingFor(Wait.forListeningPort());

    @DynamicPropertySource
    static void properties(DynamicPropertyRegistry registry) {
        registry.add("spring.datasource.url", () -> "jdbc:postgresql://" + POSTGRES.getHost() + ":"
                + POSTGRES.getMappedPort(5432) + "/axiom_g13_race");
        registry.add("spring.datasource.username", () -> "axiom");
        registry.add("spring.datasource.password", () -> "g13-isolated-test-only");
        registry.add("spring.data.redis.host", REDIS::getHost);
        registry.add("spring.data.redis.port", () -> REDIS.getMappedPort(6379));
        registry.add("iam.cerbos.authz-enabled", () -> "false");
        registry.add("iam.signing-key-path", () -> KEY_DIR.resolve("signing-key.json").toString());
        registry.add("iam.signing-key-allow-generation", () -> "true");
        registry.add("iam.secrets.master-key", UserDisableSessionRaceIT::randomMasterKey);
        registry.add("axiom.bootstrap.enabled", () -> "false");
        registry.add("iam.policy-studio.base-bundle-dir",
                () -> Path.of("..", "platform-policy", "policies").toAbsolutePath().normalize().toString());
    }

    @Autowired UserService users;
    @Autowired IamSessionService sessions;
    @Autowired ActiveTenantDirectory directory;
    @Autowired JdbcTemplate jdbc;
    @Autowired PlatformTransactionManager transactions;

    private static boolean tenantSeeded;

    @BeforeEach
    void seedTenantAndAdminContext() {
        if (!tenantSeeded) {
            jdbc.update("INSERT INTO tenants (id, name, slug) VALUES (?, 'G-13 race test', ?)", TENANT, TENANT);
            directory.activate(TENANT, "g13-race-test");
            tenantSeeded = true;
        }
        actAsTenantAdmin();
    }

    @AfterEach
    void clearSecurityContext() {
        SecurityContextHolder.clearContext();
    }

    @AfterAll
    static void removeTemporaryKeyMaterial() throws Exception {
        try (var files = Files.walk(KEY_DIR)) {
            files.sorted((a, b) -> b.getNameCount() - a.getNameCount()).forEach(p -> p.toFile().delete());
        }
    }

    // -----------------------------------------------------------------------------------------------------------------
    // Baseline
    // -----------------------------------------------------------------------------------------------------------------

    @Test
    void sessionIssuedBeforeDisableIsRevokedAndStaysDeadAfterReEnable() {
        String user = seedUser();
        UUID sid = issue(user);
        assertThat(validates(sid)).as("valid before disable").isTrue();

        disable(user);
        assertThat(status(sid)).isEqualTo("REVOKED");
        assertThat(validates(sid)).isFalse();

        enable(user);
        assertThat(status(sid)).isEqualTo("REVOKED");
        assertThat(validates(sid)).as("revoked session does not revive on re-enable").isFalse();
        assertThat(validatorAccepts(sid)).isFalse();
    }

    @Test
    void issuanceAfterDisableCommitIsRefusedAndCreatesNoSession() {
        String user = seedUser();
        disable(user);

        assertThat(issueOutcome(user)).isInstanceOf(DisabledException.class);
        assertThat(sessionCount(user)).as("no session row for a disabled principal").isZero();

        enable(user);
        assertThat(activeValidSessions(user)).as("nothing to revive after re-enable").isZero();
    }

    // -----------------------------------------------------------------------------------------------------------------
    // Forced interleavings on the principal row lock
    // -----------------------------------------------------------------------------------------------------------------

    @Test
    void disableHoldingTheLockBlocksIssuanceWhichIsThenRefused() throws Exception {
        String user = seedUser();
        ExecutorService pool = Executors.newSingleThreadExecutor();
        Future<Object> issuance;
        try {
            Future<Object>[] pending = new Future[1];
            new TransactionTemplate(transactions).executeWithoutResult(tx -> {
                users.updateUser(user, new UpdateUserRequest(null, false, null), null);   // holds the row lock
                pending[0] = pool.submit(() -> issueOutcome(user));
                awaitBlockedOnPrincipal(1);
                assertThat(pending[0].isDone()).as("issuance blocked behind the uncommitted disable").isFalse();
            });                                                                             // disable commits
            issuance = pending[0];
            assertThat(issuance.get(20, TimeUnit.SECONDS)).as("issuance observes the committed disable")
                    .isInstanceOf(DisabledException.class);
        } finally {
            pool.shutdownNow();
        }
        assertThat(sessionCount(user)).as("no session crossed the disable").isZero();

        enable(user);
        assertThat(activeValidSessions(user)).as("nothing revives after re-enable").isZero();
    }

    @Test
    void issuanceHoldingTheLockBlocksDisableWhichThenRevokesTheSession() throws Exception {
        String user = seedUser();
        ExecutorService pool = Executors.newSingleThreadExecutor();
        UUID[] sid = new UUID[1];
        try {
            Future<?>[] pendingDisable = new Future[1];
            new TransactionTemplate(transactions).executeWithoutResult(tx -> {
                sid[0] = issue(user);                                                       // holds the row lock
                pendingDisable[0] = pool.submit(() -> {
                    actAsTenantAdmin();
                    try {
                        disable(user);
                    } finally {
                        SecurityContextHolder.clearContext();
                    }
                    return null;
                });
                awaitBlockedOnPrincipal(1);
                assertThat(pendingDisable[0].isDone()).as("disable blocked behind the uncommitted issuance").isFalse();
            });                                                                             // issuance commits
            pendingDisable[0].get(20, TimeUnit.SECONDS);
        } finally {
            pool.shutdownNow();
        }
        assertThat(status(sid[0])).as("the disable saw the committed session and revoked it").isEqualTo("REVOKED");
        assertThat(validates(sid[0])).isFalse();

        enable(user);
        assertThat(validates(sid[0])).as("does not revive on re-enable").isFalse();
        assertThat(validatorAccepts(sid[0])).isFalse();
    }

    // -----------------------------------------------------------------------------------------------------------------
    // Re-enable semantics and scope
    // -----------------------------------------------------------------------------------------------------------------

    @Test
    void noOpActiveFlagDoesNotRevokeSessions() {
        String user = seedUser();
        UUID sid = issue(user);

        users.updateUser(user, new UpdateUserRequest(null, true, null), null);

        assertThat(status(sid)).isEqualTo("ACTIVE");
        assertThat(validates(sid)).isTrue();
    }

    @Test
    void reEnableSweepsAnyPreExistingActiveRowForTheUser() {
        // Simulates a row that escaped before this fix (e.g. legacy data): disabled user, ACTIVE row inserted directly.
        String user = seedUser();
        disable(user);
        UUID legacy = UUID.randomUUID();
        jdbc.update("INSERT INTO iam_sessions (id, tenant_id, principal_id, client_id, issued_at, last_seen_at, "
                + "expires_at, status) VALUES (?, ?, ?, 'g13-client', now(), now(), now() + interval '1 hour', 'ACTIVE')",
                legacy, TENANT, user);
        assertThat(validates(legacy)).as("denied while disabled (live principal check)").isFalse();

        enable(user);

        assertThat(status(legacy)).as("re-enable sweeps the stray row").isEqualTo("REVOKED");
        assertThat(validates(legacy)).isFalse();
    }

    @Test
    void customerSessionIssuanceIsUnchangedByTheWorkforceCheck() {
        // CIAM customer sessions use issue() with a customer UUID that is not a workforce principal.
        String customerId = UUID.randomUUID().toString();
        UUID sid = sessions.issue("g13-customer-" + UUID.randomUUID(), TENANT, customerId, null, "g13-customer-web",
                Instant.now().plus(5, ChronoUnit.MINUTES));
        assertThat(validates(sid)).isTrue();
        assertThat(issueForWorkforceOutcome(customerId)).as("workforce path refuses a non-principal")
                .isInstanceOf(DisabledException.class);
    }

    // -----------------------------------------------------------------------------------------------------------------
    // Unforced concurrent races
    // -----------------------------------------------------------------------------------------------------------------

    @Test
    void concurrentDisableAndIssueNeverLeaveARevivableSession() throws Exception {
        ExecutorService pool = Executors.newFixedThreadPool(2);
        int refused = 0;
        int revoked = 0;
        try {
            for (int i = 0; i < 20; i++) {
                String user = seedUser();
                CyclicBarrier start = new CyclicBarrier(2);
                Future<?> disable = pool.submit(() -> {
                    start.await(10, TimeUnit.SECONDS);
                    actAsTenantAdmin();
                    try {
                        disable(user);
                    } finally {
                        SecurityContextHolder.clearContext();
                    }
                    return null;
                });
                Future<Object> issued = pool.submit(() -> {
                    start.await(10, TimeUnit.SECONDS);
                    return issueOutcome(user);
                });
                disable.get(20, TimeUnit.SECONDS);
                Object outcome = issued.get(20, TimeUnit.SECONDS);
                if (outcome instanceof DisabledException) {
                    refused++;
                    assertThat(sessionCount(user)).as("iteration %d: refused issuance left no row", i).isZero();
                } else {
                    revoked++;
                    assertThat(status((UUID) outcome)).as("iteration %d: issued session was revoked", i)
                            .isEqualTo("REVOKED");
                }
                enable(user);
                assertThat(activeValidSessions(user)).as("iteration %d: nothing valid after re-enable", i).isZero();
            }
        } finally {
            pool.shutdownNow();
        }
        assertThat(refused + revoked).isEqualTo(20);
        System.out.println("G-13 concurrent race: issuance refused = " + refused + ", issued-then-revoked = " + revoked);
    }

    // -----------------------------------------------------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------------------------------------------------

    private void awaitBlockedOnPrincipal(int expected) {
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(15);
        int seen = -1;
        while (System.nanoTime() < deadline) {
            // Lock clause not matched textually (Hibernate 6 emits "for no key update" on PostgreSQL).
            seen = jdbc.queryForObject("""
                    SELECT count(*) FROM pg_stat_activity
                    WHERE datname = current_database() AND pid <> pg_backend_pid()
                      AND wait_event_type = 'Lock' AND query ILIKE '%principals%'
                    """, Integer.class);
            if (seen == expected) return;
            try {
                Thread.sleep(20);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new IllegalStateException(e);
            }
        }
        List<String> activity = jdbc.queryForList("""
                SELECT coalesce(wait_event_type, '-') || '/' || coalesce(wait_event, '-') || ' ' || state || ' '
                       || left(regexp_replace(query, '\\s+', ' ', 'g'), 160)
                FROM pg_stat_activity WHERE datname = current_database() AND pid <> pg_backend_pid()
                """, String.class);
        fail("expected %d call(s) blocked on the principal row lock, saw %d; activity=%s", expected, seen, activity);
    }

    private void actAsTenantAdmin() {
        Jwt jwt = Jwt.withTokenValue("g13-test-admin").header("alg", "none")
                .subject("g13-admin").claim("tenant_id", TENANT).build();
        SecurityContextHolder.getContext().setAuthentication(new JwtAuthenticationToken(jwt));
    }

    private String seedUser() {
        String id = "g13-" + UUID.randomUUID().toString().substring(0, 12);
        jdbc.update("INSERT INTO principals (id, tenant_id, username, email, password_hash, is_active) "
                + "VALUES (?, ?, ?, ?, 'not-a-login-credential', TRUE)", id, TENANT, id, id + "@g13.invalid");
        return id;
    }

    /** Workforce issuance, as used by the OAuth token customizer and /auth/login. */
    private UUID issue(String user) {
        return sessions.issueForWorkforce("g13-auth-" + UUID.randomUUID(), TENANT, user, null, "g13-client",
                Instant.now().plus(1, ChronoUnit.HOURS));
    }

    private Object issueOutcome(String user) {
        return issueForWorkforceOutcome(user);
    }

    private Object issueForWorkforceOutcome(String principalId) {
        try {
            return issue(principalId);
        } catch (DisabledException e) {
            return e;
        }
    }

    private void disable(String user) {
        users.updateUser(user, new UpdateUserRequest(null, false, null), null);
    }

    private void enable(String user) {
        users.updateUser(user, new UpdateUserRequest(null, true, null), null);
    }

    private boolean validates(UUID sid) {
        return sessions.active(sid, TENANT, Instant.now());
    }

    private boolean validatorAccepts(UUID sid) {
        Jwt token = Jwt.withTokenValue("g13-session-token").header("alg", "none")
                .subject("g13-subject").claim("sid", sid.toString()).claim("tenant_id", TENANT)
                .issuedAt(Instant.now()).expiresAt(Instant.now().plusSeconds(300)).build();
        return !new SessionTokenValidator(sessions).validate(token).hasErrors();
    }

    private String status(UUID sid) {
        return jdbc.queryForObject("SELECT status FROM iam_sessions WHERE id = ?", String.class, sid);
    }

    private int sessionCount(String user) {
        Integer n = jdbc.queryForObject("SELECT count(*) FROM iam_sessions WHERE tenant_id = ? AND principal_id = ?",
                Integer.class, TENANT, user);
        return n == null ? 0 : n;
    }

    private int activeValidSessions(String user) {
        List<UUID> ids = jdbc.queryForList("SELECT id FROM iam_sessions WHERE tenant_id = ? AND principal_id = ?",
                UUID.class, TENANT, user);
        return (int) ids.stream().filter(this::validates).count();
    }

    private static String randomMasterKey() {
        byte[] key = new byte[32];
        new SecureRandom().nextBytes(key);
        return Base64.getEncoder().encodeToString(key);
    }

    private static Path tempDir() {
        try {
            return Files.createTempDirectory("g13-race-keys");
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }
}
