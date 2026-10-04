package com.openwolf.iam.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.openwolf.iam.IamApplication;
import com.openwolf.iam.tenancy.ActiveTenantDirectory;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.DockerImageName;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;

/**
 * Operator-supplied confidential-client secrets through Axiom's real admin API, identity-control approval flow and
 * token endpoint (MockMvc over the full filter chains), on disposable PostgreSQL and Redis. Two distinct tenant
 * administrators exercise the two-person rule. Generated passwords, keys and secrets only.
 */
@Testcontainers
@SpringBootTest(classes = IamApplication.class, webEnvironment = SpringBootTest.WebEnvironment.MOCK)
@AutoConfigureMockMvc
@ExtendWith(OutputCaptureExtension.class)
class OperatorSuppliedClientSecretIT {

    private static final String TENANT = "oss-a";
    private static final String SCOPE = "oss:invoke";
    private static final String PASSWORD = UUID.randomUUID() + "-Aa1!";
    private static final Path KEY_DIR = tempDir();

    @Container
    static final GenericContainer<?> POSTGRES = new GenericContainer<>(DockerImageName.parse("postgres:16"))
            .withEnv("POSTGRES_USER", "axiom").withEnv("POSTGRES_PASSWORD", "oss-isolated-test-only")
            .withEnv("POSTGRES_DB", "axiom_oss").withExposedPorts(5432)
            .waitingFor(Wait.forLogMessage(".*database system is ready to accept connections.*", 2));

    @Container
    static final GenericContainer<?> REDIS = new GenericContainer<>(DockerImageName.parse("redis:7-alpine"))
            .withExposedPorts(6379).waitingFor(Wait.forListeningPort());

    @DynamicPropertySource
    static void properties(DynamicPropertyRegistry registry) {
        // Test-fixture opt-in: this suite's operator login still uses the legacy password-to-token endpoint, which is
        // off by default (IDP baseline secure defaults).
        registry.add("iam.auth.legacy-password-login.enabled", () -> "true");
        registry.add("spring.datasource.url", () -> "jdbc:postgresql://" + POSTGRES.getHost() + ":"
                + POSTGRES.getMappedPort(5432) + "/axiom_oss");
        registry.add("spring.datasource.username", () -> "axiom");
        registry.add("spring.datasource.password", () -> "oss-isolated-test-only");
        registry.add("spring.data.redis.host", REDIS::getHost);
        registry.add("spring.data.redis.port", () -> REDIS.getMappedPort(6379));
        registry.add("iam.cerbos.authz-enabled", () -> "false");
        registry.add("iam.signing-key-path", () -> KEY_DIR.resolve("signing-key.json").toString());
        registry.add("iam.signing-key-allow-generation", () -> "true");
        registry.add("iam.secrets.master-key", () -> Base64.getEncoder().encodeToString(bytes(32)));
        registry.add("axiom.bootstrap.enabled", () -> "false");
        registry.add("iam.oauth2.approved-business-scopes", () -> SCOPE);
        registry.add("iam.policy-studio.base-bundle-dir",
                () -> Path.of("..", "platform-policy", "policies").toAbsolutePath().normalize().toString());
    }

    @Autowired MockMvc mvc;
    @Autowired JdbcTemplate jdbc;
    @Autowired PasswordEncoder passwords;
    @Autowired ActiveTenantDirectory directory;
    @Autowired ObjectMapper json;

    private static boolean seeded;
    private static String appId;

    @BeforeEach
    void seedOnce() throws Exception {
        if (seeded) return;
        jdbc.update("INSERT INTO tenants (id, name, slug) VALUES (?, 'Supplied secret test', ?)", TENANT, TENANT);
        directory.activate(TENANT, "oss-test");
        UUID role = UUID.randomUUID();
        jdbc.update("INSERT INTO roles (id, tenant_id, name) VALUES (?, ?, 'tenant_admin')", role, TENANT);
        for (String admin : List.of("oss-alice", "oss-bob")) {
            jdbc.update("INSERT INTO principals (id, tenant_id, username, email, password_hash, is_active) "
                    + "VALUES (?, ?, ?, ?, ?, TRUE)", admin, TENANT, admin, admin + "@oss.invalid", passwords.encode(PASSWORD));
            jdbc.update("INSERT INTO principal_roles (principal_id, role_id, tenant_id) VALUES (?, ?, ?)", admin, role, TENANT);
        }
        jdbc.update("INSERT INTO principals (id, tenant_id, username, email, password_hash, is_active) "
                + "VALUES ('oss-member', ?, 'oss-member', 'm@oss.invalid', ?, TRUE)", TENANT, passwords.encode(PASSWORD));
        appId = body(send(post("/admin/tenants/" + TENANT + "/applications"), login("oss-alice"), Map.of(
                "applicationKey", "oss-app", "displayName", "oss", "audience", "agent:" + TENANT + ":oss")), 201)
                .get("id").asText();
        seeded = true;
    }

    @AfterAll
    static void removeKeys() throws Exception {
        try (var files = Files.walk(KEY_DIR)) {
            files.sorted((a, b) -> b.getNameCount() - a.getNameCount()).forEach(p -> p.toFile().delete());
        }
    }

    // -- create ------------------------------------------------------------------------------------------------------

    @Test
    void suppliedSecretIsStoredNeverReturnedAndAuthenticatesTheClient() throws Exception {
        String secret = secret();
        MvcResult created = createClient("oss-svc-1", "CONFIDENTIAL_SERVICE", secret, login("oss-alice"));
        assertThat(created.getResponse().getStatus()).isEqualTo(201);
        String responseBody = created.getResponse().getContentAsString();
        assertThat(responseBody).doesNotContain(secret);
        assertThat(json.readTree(responseBody).get("serviceSecret").isNull()).isTrue();

        assertThat(clientCredentials("oss-svc-1", secret).getResponse().getStatus()).isEqualTo(200);
        MvcResult wrong = clientCredentials("oss-svc-1", secret());
        assertThat(wrong.getResponse().getStatus()).isEqualTo(401);
        assertThat(json.readTree(wrong.getResponse().getContentAsString()).get("error").asText()).isEqualTo("invalid_client");
        assertNoSecretInAudit(secret);
    }

    @Test
    void repeatedCreateIsAConflictThatRevealsNothingAboutTheSecret() throws Exception {
        String secret = secret();
        String admin = login("oss-alice");
        assertThat(createClient("oss-svc-2", "CONFIDENTIAL_SERVICE", secret, admin).getResponse().getStatus()).isEqualTo(201);
        MvcResult same = createClient("oss-svc-2", "CONFIDENTIAL_SERVICE", secret, admin);
        MvcResult different = createClient("oss-svc-2", "CONFIDENTIAL_SERVICE", secret(), admin);
        assertThat(same.getResponse().getStatus()).isEqualTo(409);
        assertThat(different.getResponse().getStatus()).isEqualTo(409);
        assertThat(errorMessage(same)).isEqualTo(errorMessage(different));
        assertThat(clientCredentials("oss-svc-2", secret).getResponse().getStatus()).as("original kept").isEqualTo(200);
    }

    @Test
    void publicClientsAndMalformedSecretsAreRejectedWithoutEchoOrSideEffect(CapturedOutput output) throws Exception {
        String admin = login("oss-alice");
        String secret = secret();
        MvcResult publicClient = createClient("oss-web-1", "PUBLIC_BROWSER", secret, admin);
        assertThat(publicClient.getResponse().getStatus()).isEqualTo(400);
        String weak = "weak-" + UUID.randomUUID();
        MvcResult malformed = createClient("oss-svc-3", "CONFIDENTIAL_SERVICE", weak, admin);
        assertThat(malformed.getResponse().getStatus()).isEqualTo(400);
        assertThat(errorMessage(malformed)).isEqualTo(OperatorSuppliedClientSecrets.FORMAT_MESSAGE);
        for (MvcResult r : List.of(publicClient, malformed)) {
            assertThat(r.getResponse().getContentAsString()).doesNotContain(secret).doesNotContain(weak);
        }
        assertThat(jdbc.queryForObject("SELECT count(*) FROM tenant_application_clients WHERE client_id IN "
                + "('oss-web-1','oss-svc-3')", Integer.class)).isZero();
        assertThat(output.getAll()).doesNotContain(secret).doesNotContain(weak);
    }

    @Test
    void malformedJsonCarryingASecretIsNotLogged(CapturedOutput output) throws Exception {
        String secret = secret();
        MvcResult result = mvc.perform(post("/admin/tenants/" + TENANT + "/applications/" + appId + "/clients")
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + login("oss-alice")).contentType(MediaType.APPLICATION_JSON)
                .content("{\"clientId\":\"oss-svc-4\",\"clientType\":\"CONFIDENTIAL_SERVICE\",\"clientSecret\":" + secret + "}"))
                .andReturn();
        assertThat(result.getResponse().getStatus()).isEqualTo(400);
        assertThat(result.getResponse().getContentAsString()).doesNotContain(secret);
        assertThat(output.getAll()).contains("Malformed request body").doesNotContain(secret);
    }

    @Test
    void onlyTenantAdministratorsMayCreateClients() throws Exception {
        MvcResult denied = createClient("oss-svc-5", "CONFIDENTIAL_SERVICE", secret(), login("oss-member"));
        assertThat(denied.getResponse().getStatus()).isEqualTo(403);
    }

    // -- approval-gated rotation ----------------------------------------------------------------------------------------

    @Test
    void rotationToASuppliedSecretRequiresASecondAdministratorAndNeverReturnsIt() throws Exception {
        String alice = login("oss-alice");
        String bob = login("oss-bob");
        String original = secret();
        JsonNode client = body(createClient("oss-svc-6", "CONFIDENTIAL_SERVICE", original, alice), 201).get("client");
        String replacement = secret();
        String recoveryId = secret();

        // The direct rotation endpoint stays approval-gated.
        assertThat(send(post("/admin/tenants/" + TENANT + "/applications/" + appId + "/clients/" + client.get("id").asText()
                + "/rotate-secret"), alice, Map.of("expectedRevision", client.get("revision").asLong()))
                .getResponse().getStatus()).isEqualTo(409);

        MvcResult proposed = send(post("/admin/tenants/" + TENANT + "/identity-control-requests"), alice, Map.of(
                "action", "ROTATE_APPLICATION_CLIENT_SECRET", "targetType", "APPLICATION_CLIENT",
                "targetId", client.get("id").asText(), "expectedTargetRevision", client.get("revision").asLong(),
                "payload", Map.of("clientSecret", replacement, "recoveryId", recoveryId)));
        JsonNode request = body(proposed, 201);
        assertThat(proposed.getResponse().getContentAsString()).doesNotContain(replacement);
        // The public fingerprint lets the script recover a lost response without hashing the replacement secret.
        assertThat(request.get("payloadHash").asText()).isEqualTo(java.util.HexFormat.of().formatHex(
                java.security.MessageDigest.getInstance("SHA-256").digest(
                        ("client-secret-rotation:" + recoveryId).getBytes(StandardCharsets.UTF_8))));
        String base = "/admin/tenants/" + TENANT + "/identity-control-requests/" + request.get("id").asText();

        assertThat(send(post(base + "/approve"), alice, Map.of("expectedRevision", 1)).getResponse().getStatus())
                .as("initiator cannot approve").isEqualTo(409);
        assertThat(send(post(base + "/apply"), alice, Map.of("expectedRevision", 1)).getResponse().getStatus())
                .as("not applicable before approval").isEqualTo(409);
        assertThat(clientCredentials("oss-svc-6", original).getResponse().getStatus()).isEqualTo(200);

        body(send(post(base + "/approve"), bob, Map.of("expectedRevision", 1)), 200);
        MvcResult applied = send(post(base + "/apply"), bob, Map.of("expectedRevision", 2));
        JsonNode appliedBody = body(applied, 200);
        assertThat(appliedBody.get("oneTimeSecret").isNull()).isTrue();
        assertThat(applied.getResponse().getContentAsString()).doesNotContain(replacement);

        assertThat(clientCredentials("oss-svc-6", original).getResponse().getStatus()).as("old secret").isEqualTo(401);
        assertThat(clientCredentials("oss-svc-6", replacement).getResponse().getStatus()).as("new secret").isEqualTo(200);

        JsonNode replay = body(send(post(base + "/apply"), bob, Map.of("expectedRevision", 3)), 200);
        assertThat(replay.get("oneTimeSecret").isNull()).isTrue();
        assertThat(clientCredentials("oss-svc-6", replacement).getResponse().getStatus()).as("replay is a no-op").isEqualTo(200);
        assertNoSecretInAudit(original);
        assertNoSecretInAudit(replacement);
        assertThat(jdbc.queryForObject("SELECT count(*) FROM identity_control_requests WHERE payload_ciphertext LIKE ?",
                Integer.class, "%" + replacement + "%")).as("payload encrypted at rest").isZero();
    }

    @Test
    void malformedRotationPayloadIsRejectedAtProposal() throws Exception {
        String alice = login("oss-alice");
        JsonNode client = body(createClient("oss-svc-7", "CONFIDENTIAL_SERVICE", secret(), alice), 201).get("client");
        int before = jdbc.queryForObject("SELECT count(*) FROM identity_control_requests", Integer.class);
        for (Map<String, Object> payload : List.<Map<String, Object>>of(Map.of("clientSecret", "weak"),
                Map.of("clientSecret", secret(), "extra", true), Map.of("replacement", secret()))) {
            MvcResult rejected = send(post("/admin/tenants/" + TENANT + "/identity-control-requests"), alice, Map.of(
                    "action", "ROTATE_APPLICATION_CLIENT_SECRET", "targetType", "APPLICATION_CLIENT",
                    "targetId", client.get("id").asText(), "expectedTargetRevision", client.get("revision").asLong(),
                    "payload", payload));
            assertThat(rejected.getResponse().getStatus()).as(payload.keySet().toString()).isEqualTo(400);
        }
        assertThat(jdbc.queryForObject("SELECT count(*) FROM identity_control_requests", Integer.class)).isEqualTo(before);
    }

    // -- credential boundary for externally issued secrets ---------------------------------------------------------

    @Test
    void identitySourceSecretProposalExposesNoGuessableDigest() throws Exception {
        String weak = "Autumn2026!" + UUID.randomUUID().toString().substring(0, 4);
        String canonical = "{\"clientSecret\":\"" + weak + "\"}";
        String unkeyed = java.util.HexFormat.of().formatHex(java.security.MessageDigest.getInstance("SHA-256")
                .digest(canonical.getBytes(StandardCharsets.UTF_8)));
        MvcResult proposed = send(post("/admin/tenants/" + TENANT + "/identity-control-requests"), login("oss-alice"),
                Map.of("action", "ROTATE_IDENTITY_SOURCE_SECRET", "targetType", "IDENTITY_SOURCE",
                        "targetId", UUID.randomUUID().toString(), "expectedTargetRevision", 1,
                        "payload", Map.of("clientSecret", weak)));
        JsonNode request = body(proposed, 201);
        assertThat(request.get("payloadHash").asText()).matches("[0-9a-f]{64}").isNotEqualTo(unkeyed);
        assertThat(proposed.getResponse().getContentAsString()).doesNotContain(weak).doesNotContain(unkeyed);
        assertThat(jdbc.queryForObject("SELECT count(*) FROM identity_control_requests WHERE payload_hash = ? "
                + "OR payload_ciphertext LIKE ?", Integer.class, unkeyed, "%" + weak + "%")).isZero();
        assertNoSecretInAudit(weak);
        assertNoSecretInAudit(unkeyed);
        // A malformed identity-source payload is refused before anything is stored.
        int before = jdbc.queryForObject("SELECT count(*) FROM identity_control_requests", Integer.class);
        assertThat(send(post("/admin/tenants/" + TENANT + "/identity-control-requests"), login("oss-alice"), Map.of(
                "action", "ROTATE_IDENTITY_SOURCE_SECRET", "targetType", "IDENTITY_SOURCE",
                "targetId", UUID.randomUUID().toString(), "expectedTargetRevision", 1,
                "payload", Map.of("clientSecret", weak, "echo", weak))).getResponse().getStatus()).isEqualTo(400);
        assertThat(jdbc.queryForObject("SELECT count(*) FROM identity_control_requests", Integer.class)).isEqualTo(before);
    }

    @Test
    void v30MigrationRemovesLegacyUnkeyedDigestsAndExpiresApplicableSecretRequests() throws Exception {
        String legacyDigest = "a".repeat(64);
        UUID pending = legacyRow("PENDING", "ciphertext", legacyDigest);
        UUID approved = legacyRow("APPROVED", "ciphertext", legacyDigest);
        UUID applied = legacyRow("APPLIED", "ciphertext", legacyDigest);
        UUID payloadFree = legacyRow("PENDING", null, legacyDigest);
        String sql = Files.readString(Path.of("src/main/resources/db/migration/V30__identity_control_unkeyed_secret_digest_removal.sql"));
        for (String statement : sql.replaceAll("(?m)^--.*$", "").split(";")) {
            if (!statement.isBlank()) jdbc.update(statement);
        }
        assertThat(row(pending)).containsEntry("status", "EXPIRED").containsEntry("payload_hash", "legacy-unkeyed-digest-removed");
        assertThat(row(approved)).containsEntry("status", "EXPIRED").containsEntry("payload_hash", "legacy-unkeyed-digest-removed");
        assertThat(row(applied)).containsEntry("status", "APPLIED").containsEntry("payload_hash", "legacy-unkeyed-digest-removed");
        assertThat(row(payloadFree)).containsEntry("status", "PENDING").containsEntry("payload_hash", legacyDigest);
    }

    private UUID legacyRow(String status, String ciphertext, String digest) {
        UUID id = UUID.randomUUID();
        boolean approved = !status.equals("PENDING");
        jdbc.update("INSERT INTO identity_control_requests (id, tenant_id, action, target_type, target_id, payload_hash, "
                        + "payload_ciphertext, initiator_principal_id, expires_at, expected_target_revision, status, "
                        + "approver_principal_id, approved_at) VALUES (?, ?, 'ROTATE_IDENTITY_SOURCE_SECRET', 'IDENTITY_SOURCE', "
                        + "?, ?, ?, 'oss-alice', now() + interval '10 minutes', 1, ?, ?, ?)",
                id, TENANT, UUID.randomUUID(), digest, ciphertext, status, approved ? "oss-bob" : null,
                approved ? java.sql.Timestamp.from(java.time.Instant.now()) : null);
        return id;
    }

    private Map<String, Object> row(UUID id) {
        return jdbc.queryForMap("SELECT status, payload_hash FROM identity_control_requests WHERE id = ?", id);
    }

    // -- helpers ---------------------------------------------------------------------------------------------------------

    private MvcResult createClient(String clientId, String type, String secret, String bearer) throws Exception {
        Map<String, Object> request = new java.util.HashMap<>(Map.of("clientId", clientId, "clientType", type,
                "redirectUris", type.equals("PUBLIC_BROWSER") ? List.of("https://portal.example/cb") : List.of(),
                "postLogoutRedirectUris", List.of(),
                "scopes", type.equals("PUBLIC_BROWSER") ? List.of("openid") : List.of(SCOPE)));
        if (secret != null) request.put("clientSecret", secret);
        return send(post("/admin/tenants/" + TENANT + "/applications/" + appId + "/clients"), bearer, request);
    }

    private MvcResult clientCredentials(String clientId, String secret) throws Exception {
        return mvc.perform(post("/oauth/token").contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .header(HttpHeaders.AUTHORIZATION, "Basic " + Base64.getEncoder().encodeToString(
                        (clientId + ":" + secret).getBytes(StandardCharsets.UTF_8)))
                .param("grant_type", "client_credentials").param("scope", SCOPE)).andReturn();
    }

    private void assertNoSecretInAudit(String secret) {
        assertThat(jdbc.queryForObject("SELECT count(*) FROM audit_log WHERE coalesce(before_state::text, '') LIKE ? "
                + "OR coalesce(after_state::text, '') LIKE ?", Integer.class, "%" + secret + "%", "%" + secret + "%")).isZero();
    }

    private String errorMessage(MvcResult result) throws Exception {
        return json.readTree(result.getResponse().getContentAsString()).path("message").asText();
    }

    private String login(String user) throws Exception {
        MvcResult login = mvc.perform(post("/auth/login").contentType(MediaType.APPLICATION_JSON)
                .content(json.writeValueAsString(Map.of("username", user, "password", PASSWORD)))).andReturn();
        assertThat(login.getResponse().getStatus()).as("login " + user).isEqualTo(200);
        return json.readTree(login.getResponse().getContentAsString()).get("accessToken").asText();
    }

    private MvcResult send(MockHttpServletRequestBuilder request, String bearer, Object body) throws Exception {
        return mvc.perform(request.header(HttpHeaders.AUTHORIZATION, "Bearer " + bearer)
                .contentType(MediaType.APPLICATION_JSON).content(json.writeValueAsString(body))).andReturn();
    }

    private JsonNode body(MvcResult result, int expected) throws Exception {
        assertThat(result.getResponse().getStatus()).as("%s -> %s", result.getRequest().getRequestURI(),
                result.getResponse().getContentAsString()).isEqualTo(expected);
        return json.readTree(result.getResponse().getContentAsString());
    }

    private static String secret() {
        String value = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes(32));
        return value.chars().distinct().count() >= 16 ? value : secret();
    }

    private static byte[] bytes(int n) {
        byte[] b = new byte[n];
        new SecureRandom().nextBytes(b);
        return b;
    }

    private static Path tempDir() {
        try {
            return Files.createTempDirectory("oss-keys");
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }
}
