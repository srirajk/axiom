package com.openwolf.iam.policystudio.breakglass;

import com.openwolf.iam.IamApplication;
import com.openwolf.iam.policystudio.api.StudioSessionStore;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.util.ReflectionTestUtils;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.DockerImageName;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.sql.Timestamp;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;

/**
 * Break-glass crash window: the C5 promotion committed (the emergency grant is enforced) but the process died before
 * {@link BreakGlassIssuanceService} saved the issuance as ACTIVATED. The row is left PENDING and the pending grant in
 * {@link StudioSessionStore} is lost with the process.
 *
 * <p>This test reproduces that durable state directly (a PENDING issuance row plus the committed promotion ledger row
 * keyed {@code break-glass:<grantId>}) in a freshly started application, so nothing is held in memory, and asserts
 * that the scheduled reconciler entry point recovers it using only durable state: ACTIVATED with the recorded bundle
 * ids, bundle lineage, exactly one GRANTED audit, no second promotion. Missing, FAILED or mismatched promotion records
 * must leave the row PENDING with no audit. One bad row must not stop recovery of the others.
 *
 * <p>Isolation: Testcontainers PostgreSQL and Redis for this class only (random localhost ports; removed by
 * Testcontainers/Ryuk); scheduled reconcilers are pushed out to one hour so only the test drives them; generated
 * secrets; no external system.
 */
@Testcontainers
@SpringBootTest(classes = IamApplication.class, webEnvironment = SpringBootTest.WebEnvironment.NONE)
class BreakGlassPendingRecoveryIT {

    private static final String TENANT = "bg-test";
    private static final Path KEY_DIR = tempDir();

    @Container
    static final GenericContainer<?> POSTGRES = new GenericContainer<>(DockerImageName.parse("postgres:16"))
            .withEnv("POSTGRES_USER", "axiom")
            .withEnv("POSTGRES_PASSWORD", "bg-isolated-test-only")
            .withEnv("POSTGRES_DB", "axiom_bg")
            .withExposedPorts(5432)
            .waitingFor(Wait.forLogMessage(".*database system is ready to accept connections.*", 2));

    @Container
    static final GenericContainer<?> REDIS = new GenericContainer<>(DockerImageName.parse("redis:7-alpine"))
            .withExposedPorts(6379)
            .waitingFor(Wait.forListeningPort());

    @DynamicPropertySource
    static void properties(DynamicPropertyRegistry registry) {
        registry.add("spring.datasource.url", () -> "jdbc:postgresql://" + POSTGRES.getHost() + ":"
                + POSTGRES.getMappedPort(5432) + "/axiom_bg");
        registry.add("spring.datasource.username", () -> "axiom");
        registry.add("spring.datasource.password", () -> "bg-isolated-test-only");
        registry.add("spring.data.redis.host", REDIS::getHost);
        registry.add("spring.data.redis.port", () -> REDIS.getMappedPort(6379));
        registry.add("iam.cerbos.authz-enabled", () -> "false");
        registry.add("iam.signing-key-path", () -> KEY_DIR.resolve("signing-key.json").toString());
        registry.add("iam.signing-key-allow-generation", () -> "true");
        registry.add("iam.secrets.master-key", BreakGlassPendingRecoveryIT::randomKey);
        registry.add("axiom.bootstrap.enabled", () -> "false");
        registry.add("iam.policy-studio.base-bundle-dir",
                () -> Path.of("..", "platform-policy", "policies").toAbsolutePath().normalize().toString());
        // Only the test drives reconciliation.
        registry.add("iam.break-glass.issuance-reconcile-ms", () -> "3600000");
        registry.add("iam.break-glass.use-reconcile-ms", () -> "3600000");
        registry.add("iam.break-glass.cerbos-import-ms", () -> "3600000");
    }

    @Autowired BreakGlassIssuanceService service;
    @Autowired StudioSessionStore sessionStore;
    @Autowired JdbcTemplate jdbc;

    private static boolean seeded;

    @BeforeEach
    void seedTenantOnce() {
        if (seeded) return;
        jdbc.update("INSERT INTO tenants (id, name, slug) VALUES (?, 'Break-glass recovery test', ?)", TENANT, TENANT);
        seeded = true;
    }

    @AfterAll
    static void removeTemporaryKeyMaterial() throws Exception {
        try (var files = Files.walk(KEY_DIR)) {
            files.sorted((a, b) -> b.getNameCount() - a.getNameCount()).forEach(p -> p.toFile().delete());
        }
    }

    // -----------------------------------------------------------------------------------------------------------------

    @Test
    void promotedButPendingIssuanceIsRecoveredAfterRestartWithEmptySessionStore() {
        @SuppressWarnings("unchecked")
        Map<String, ?> inMemoryGrants = (Map<String, ?>) ReflectionTestUtils.getField(sessionStore, "grants");
        assertThat(inMemoryGrants).as("restart: no pending grant held in memory").isEmpty();

        String grant = pendingIssuance(TENANT, "bob");
        promotion(grant, TENANT, "bob", "PROMOTION", "PROMOTED", "b_base", "b_" + grant);

        assertThatCode(service::scheduledReconcileActivated).doesNotThrowAnyException();

        assertThat(state(grant)).isEqualTo("ACTIVATED");
        assertThat(jdbc.queryForObject("SELECT active_bundle_id FROM break_glass_issuances WHERE grant_id = ?",
                String.class, grant)).isEqualTo("b_" + grant);
        assertThat(jdbc.queryForObject("SELECT from_bundle_id FROM break_glass_issuances WHERE grant_id = ?",
                String.class, grant)).isEqualTo("b_base");
        assertThat(auditRecorded(grant)).isTrue();
        assertThat(grantedAudits(grant)).as("exactly one GRANTED audit").isEqualTo(1);
        assertThat(lineage("b_" + grant, grant)).as("bundle lineage recorded").isEqualTo(1);

        // Idempotent: a second pass (or another replica) changes nothing.
        service.scheduledReconcileActivated();
        assertThat(grantedAudits(grant)).isEqualTo(1);
        assertThat(promotions(grant)).as("no second promotion").isEqualTo(1);
        assertThat(lineage("b_" + grant, grant)).isEqualTo(1);
    }

    @Test
    void missingPromotionLeavesIssuancePendingWithoutAudit() {
        String grant = pendingIssuance(TENANT, "bob");

        service.scheduledReconcileActivated();

        assertThat(state(grant)).isEqualTo("PENDING");
        assertThat(grantedAudits(grant)).isZero();
        assertThat(promotions(grant)).as("reconciler never promotes").isZero();
    }

    @Test
    void failedOrInFlightPromotionLeavesIssuancePendingWithoutAudit() {
        // FAILED is also the initial ledger state of an in-flight promotion, so it is never treated as success.
        String grant = pendingIssuance(TENANT, "bob");
        promotion(grant, TENANT, "bob", "PROMOTION", "FAILED", "b_base", "b_" + grant);

        service.scheduledReconcileActivated();

        assertThat(state(grant)).isEqualTo("PENDING");
        assertThat(grantedAudits(grant)).isZero();
    }

    @Test
    void mismatchedPromotionRecordLeavesIssuancePendingWithoutAudit() {
        String otherTenant = pendingIssuance(TENANT, "bob");
        promotion(otherTenant, "someone-else", "bob", "PROMOTION", "PROMOTED", "b_base", "b_x1");
        String otherApprover = pendingIssuance(TENANT, "bob");
        promotion(otherApprover, TENANT, "mallory", "PROMOTION", "PROMOTED", "b_base", "b_x2");
        String rollback = pendingIssuance(TENANT, "bob");
        promotion(rollback, TENANT, "bob", "ROLLBACK", "PROMOTED", "b_base", "b_x3");

        service.scheduledReconcileActivated();

        for (String grant : new String[] {otherTenant, otherApprover, rollback}) {
            assertThat(state(grant)).as(grant).isEqualTo("PENDING");
            assertThat(grantedAudits(grant)).as(grant).isZero();
        }
    }

    @Test
    void oneBadRowDoesNotPreventRecoveryOfOthers() {
        // A corrupt ACTIVATED outbox row and a corrupt PENDING row (unparseable scope) sit alongside a good row.
        String badActivated = pendingIssuance(TENANT, "bob");
        jdbc.update("UPDATE break_glass_issuances SET state = 'ACTIVATED', active_bundle_id = 'b_bad', scope = 'bg-test..corrupt' "
                + "WHERE grant_id = ?", badActivated);
        String badPending = pendingIssuance(TENANT, "bob");
        promotion(badPending, TENANT, "bob", "PROMOTION", "PROMOTED", "b_base", "b_" + badPending);
        jdbc.update("UPDATE break_glass_issuances SET scope = 'bg-test..corrupt' WHERE grant_id = ?", badPending);
        String good = pendingIssuance(TENANT, "bob");
        promotion(good, TENANT, "bob", "PROMOTION", "PROMOTED", "b_base", "b_" + good);

        assertThatCode(service::scheduledReconcileActivated).doesNotThrowAnyException();

        assertThat(state(good)).isEqualTo("ACTIVATED");
        assertThat(auditRecorded(good)).isTrue();
        assertThat(grantedAudits(good)).isEqualTo(1);
        assertThat(auditRecorded(badActivated)).isFalse();
        assertThat(lastError(badActivated)).as("bad row records its error").isNotBlank();
        assertThat(auditRecorded(badPending)).isFalse();
        assertThat(lastError(badPending)).isNotBlank();
    }

    // -----------------------------------------------------------------------------------------------------------------

    private String pendingIssuance(String tenant, String approver) {
        String grant = "bg-" + UUID.randomUUID().toString().substring(0, 12);
        Instant issued = Instant.now().truncatedTo(ChronoUnit.SECONDS);
        jdbc.update("INSERT INTO break_glass_issuances (grant_id, tenant_id, scope, resource_kind, action, role_name, "
                + "issued_at, expires_at, requested_by, justification, approved_by, correlation_id, state) "
                + "VALUES (?, ?, ?, 'iam-resource', 'read', 'tenant_admin', ?, ?, 'alice', 'incident', ?, ?, 'PENDING')",
                grant, tenant, tenant, Timestamp.from(issued), Timestamp.from(issued.plus(30, ChronoUnit.MINUTES)),
                approver, "corr-" + grant);
        return grant;
    }

    private void promotion(String grant, String tenant, String approver, String kind, String status,
                           String from, String to) {
        jdbc.update("INSERT INTO bundle_promotions (id, idempotency_key, tenant_id, from_bundle_id, to_bundle_id, "
                + "consequence_review_hash, approver_id, kind, status, directory_version) "
                + "VALUES (?, ?, ?, ?, ?, 'crh-test', ?, ?, ?, ?)",
                UUID.randomUUID(), "break-glass:" + grant, tenant, from, to, approver, kind, status,
                "PROMOTED".equals(status) ? 2L : null);
    }

    private String state(String grant) {
        return jdbc.queryForObject("SELECT state FROM break_glass_issuances WHERE grant_id = ?", String.class, grant);
    }

    private boolean auditRecorded(String grant) {
        return Boolean.TRUE.equals(jdbc.queryForObject(
                "SELECT audit_recorded FROM break_glass_issuances WHERE grant_id = ?", Boolean.class, grant));
    }

    private String lastError(String grant) {
        return jdbc.queryForObject("SELECT last_error FROM break_glass_issuances WHERE grant_id = ?", String.class,
                grant);
    }

    private int grantedAudits(String grant) {
        Integer n = jdbc.queryForObject("SELECT count(*) FROM audit_log WHERE action = 'break_glass.granted' "
                + "AND correlation_id = ?", Integer.class, "corr-" + grant);
        return n == null ? 0 : n;
    }

    private int promotions(String grant) {
        Integer n = jdbc.queryForObject("SELECT count(*) FROM bundle_promotions WHERE idempotency_key = ?",
                Integer.class, "break-glass:" + grant);
        return n == null ? 0 : n;
    }

    private int lineage(String bundle, String grant) {
        Integer n = jdbc.queryForObject("SELECT count(*) FROM break_glass_bundle_grants WHERE bundle_id = ? "
                + "AND grant_id = ?", Integer.class, bundle, grant);
        return n == null ? 0 : n;
    }

    private static String randomKey() {
        byte[] key = new byte[32];
        new SecureRandom().nextBytes(key);
        return Base64.getEncoder().encodeToString(key);
    }

    private static Path tempDir() {
        try {
            return Files.createTempDirectory("bg-keys");
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }
}
