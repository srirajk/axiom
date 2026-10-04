package com.openwolf.iam.auth;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.openwolf.iam.IamApplication;
import com.openwolf.iam.tenancy.ActiveTenantDirectory;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.web.util.UriComponentsBuilder;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.DockerImageName;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;

/**
 * Regression: can a tenant admin mint an application token that the Axiom API accepts as platform_admin?
 *
 * <p>Attack: a tenant application whose audience is the Axiom API audience ({@code axiom-api}), an application role
 * whose key is {@code platform_admin}, a membership for the attacker, then an ordinary PKCE login. Application role
 * keys are emitted in the access token's {@code roles} claim, and the API maps {@code roles} to Spring authorities.
 *
 * <p>Runs the real filter chains through MockMvc on disposable PostgreSQL and Redis containers (random localhost
 * ports, removed after the class by Testcontainers/Ryuk). Credentials and keys are generated per run.
 */
@Testcontainers
@SpringBootTest(classes = IamApplication.class, webEnvironment = SpringBootTest.WebEnvironment.MOCK)
@AutoConfigureMockMvc
class ApplicationAudienceEscalationIT {

    private static final String TENANT = "esc-test";
    private static final String ADMIN_ID = "esc-tenant-admin";
    // Separate tenant for the create-path test: (tenant_id, audience) is unique, so it must not share a tenant with
    // the pre-existing reserved-audience application inserted by the legacy-data test.
    private static final String TENANT_B = "esc-test-b";
    private static final String ADMIN_B = "esc-tenant-admin-b";
    private static final String CALLBACK = "http://127.0.0.1:9/callback";
    private static final String CONSOLE_CALLBACK = "http://localhost:5180/callback";
    private static final String PASSWORD = UUID.randomUUID() + "-Aa1!";
    private static final Path KEY_DIR = tempDir();

    @Container
    static final GenericContainer<?> POSTGRES = new GenericContainer<>(DockerImageName.parse("postgres:16"))
            .withEnv("POSTGRES_USER", "axiom")
            .withEnv("POSTGRES_PASSWORD", "esc-isolated-test-only")
            .withEnv("POSTGRES_DB", "axiom_esc")
            .withExposedPorts(5432)
            .waitingFor(Wait.forLogMessage(".*database system is ready to accept connections.*", 2));

    @Container
    static final GenericContainer<?> REDIS = new GenericContainer<>(DockerImageName.parse("redis:7-alpine"))
            .withExposedPorts(6379)
            .waitingFor(Wait.forListeningPort());

    @DynamicPropertySource
    static void properties(DynamicPropertyRegistry registry) {
        // Test-fixture opt-in: this suite's operator login still uses the legacy password-to-token endpoint, which is
        // off by default (IDP baseline secure defaults).
        registry.add("iam.auth.legacy-password-login.enabled", () -> "true");
        registry.add("spring.datasource.url", () -> "jdbc:postgresql://" + POSTGRES.getHost() + ":"
                + POSTGRES.getMappedPort(5432) + "/axiom_esc");
        registry.add("spring.datasource.username", () -> "axiom");
        registry.add("spring.datasource.password", () -> "esc-isolated-test-only");
        registry.add("spring.data.redis.host", REDIS::getHost);
        registry.add("spring.data.redis.port", () -> REDIS.getMappedPort(6379));
        registry.add("iam.cerbos.authz-enabled", () -> "false");
        registry.add("iam.signing-key-path", () -> KEY_DIR.resolve("signing-key.json").toString());
        registry.add("iam.signing-key-allow-generation", () -> "true");
        registry.add("iam.secrets.master-key", ApplicationAudienceEscalationIT::randomKey);
        registry.add("axiom.bootstrap.enabled", () -> "false");
        registry.add("iam.oauth2.axiom-admin.redirect-uri", () -> CONSOLE_CALLBACK);
        registry.add("iam.policy-studio.base-bundle-dir",
                () -> Path.of("..", "platform-policy", "policies").toAbsolutePath().normalize().toString());
    }

    @Autowired MockMvc mvc;
    @Autowired JdbcTemplate jdbc;
    @Autowired PasswordEncoder passwords;
    @Autowired ActiveTenantDirectory directory;
    @Autowired ObjectMapper json;

    private static boolean seeded;

    @BeforeEach
    void seedTenantAdminsOnce() {
        if (seeded) return;
        seedTenantAdmin(TENANT, ADMIN_ID);
        seedTenantAdmin(TENANT_B, ADMIN_B);
        seeded = true;
    }

    private void seedTenantAdmin(String tenant, String adminId) {
        jdbc.update("INSERT INTO tenants (id, name, slug) VALUES (?, 'Escalation test', ?)", tenant, tenant);
        directory.activate(tenant, "esc-test");
        jdbc.update("INSERT INTO principals (id, tenant_id, username, email, password_hash, is_active) "
                + "VALUES (?, ?, ?, ?, ?, TRUE)", adminId, tenant, adminId, adminId + "@esc.invalid",
                passwords.encode(PASSWORD));
        UUID role = UUID.randomUUID();
        jdbc.update("INSERT INTO roles (id, tenant_id, name) VALUES (?, ?, 'tenant_admin')", role, tenant);
        jdbc.update("INSERT INTO principal_roles (principal_id, role_id, tenant_id) VALUES (?, ?, ?)",
                adminId, role, tenant);
    }

    @AfterAll
    static void removeTemporaryKeyMaterial() throws Exception {
        try (var files = Files.walk(KEY_DIR)) {
            files.sorted((a, b) -> b.getNameCount() - a.getNameCount()).forEach(p -> p.toFile().delete());
        }
    }

    // -----------------------------------------------------------------------------------------------------------------
    // Controls
    // -----------------------------------------------------------------------------------------------------------------

    @Test
    void controlTenantAdminLoginTokenIsNotPlatformAdmin() throws Exception {
        String tenantAdmin = tenantAdminToken();
        assertThat(status(get("/admin/tenants"), tenantAdmin)).as("platform-only route").isEqualTo(403);
        assertThat(status(get("/admin/tenants/" + TENANT + "/applications"), tenantAdmin))
                .as("tenant_admin route").isEqualTo(200);
    }

    @Test
    void controlAxiomAdminConsoleTokenIsStillAccepted() throws Exception {
        String console = pkceToken("axiom-admin", CONSOLE_CALLBACK, "openid profile roles");
        Map<String, Object> claims = claims(console);
        assertThat(claims.get("client_id")).isEqualTo("axiom-admin");
        assertThat(status(get("/admin/tenants/" + TENANT + "/applications"), console))
                .as("platform-owned console client keeps API access").isEqualTo(200);
    }

    // -----------------------------------------------------------------------------------------------------------------
    // Escalation attempts
    // -----------------------------------------------------------------------------------------------------------------

    @Test
    void tenantAdminCannotCreateApplicationWithTheReservedApiAudience() throws Exception {
        String tenantAdmin = tenantAdminToken(ADMIN_B);
        MvcResult created = send(post("/admin/tenants/" + TENANT_B + "/applications"), tenantAdmin, Map.of(
                "applicationKey", "esc-new-app", "displayName", "Escalation attempt",
                "audience", AxiomApiJwtValidator.AUDIENCE));

        assertThat(created.getResponse().getStatus())
                .as("reserved audience refused; body=%s", created.getResponse().getContentAsString())
                .isEqualTo(400);
        assertThat(created.getResponse().getContentAsString()).contains("reserved");
        assertThat(jdbc.queryForObject("SELECT count(*) FROM tenant_applications WHERE audience = ? "
                + "AND application_key = 'esc-new-app'", Integer.class, AxiomApiJwtValidator.AUDIENCE)).isZero();
    }

    @Test
    void preExistingReservedAudienceApplicationCannotMintAPlatformAdminApiToken() throws Exception {
        String tenantAdmin = tenantAdminToken();
        // Legacy data: an application that already carries the reserved audience (created before the fix).
        UUID appId = UUID.randomUUID();
        jdbc.update("INSERT INTO tenant_applications (id, tenant_id, application_key, display_name, audience, status) "
                + "VALUES (?, ?, 'esc-legacy-app', 'Legacy reserved audience', ?, 'ACTIVE')",
                appId, TENANT, AxiomApiJwtValidator.AUDIENCE);
        String base = "/admin/tenants/" + TENANT + "/applications/" + appId;

        // Everything below uses only tenant_admin authority.
        String clientId = "esc-legacy-web";
        assertThat(send(post(base + "/clients"), tenantAdmin, Map.of("clientId", clientId,
                "clientType", "PUBLIC_BROWSER", "redirectUris", List.of(CALLBACK), "postLogoutRedirectUris", List.of(),
                "scopes", List.of("openid"))).getResponse().getStatus()).isEqualTo(201);
        JsonNode role = body(send(post(base + "/access/roles"), tenantAdmin, Map.of("roleKey", "platform_admin",
                "displayName", "Not really a platform admin", "permissions", List.of())), 201);
        JsonNode membership = body(send(post(base + "/access/memberships"), tenantAdmin, Map.of(
                "principalId", ADMIN_ID, "assignmentSource", "esc-test")), 201);
        body(send(post(base + "/access/memberships/" + membership.get("id").asText() + "/roles"), tenantAdmin,
                Map.of("roleId", role.get("id").asText(), "assignmentSource", "esc-test")), 200);

        String appToken = pkceToken(clientId, CALLBACK, "openid");
        Map<String, Object> claims = claims(appToken);
        Object aud = claims.get("aud");
        assertThat(aud instanceof List<?> list ? list : List.of(aud)).as("attack token targets the API audience")
                .isEqualTo(List.of(AxiomApiJwtValidator.AUDIENCE));
        assertThat(claims.get("roles")).as("attack token carries the application role key")
                .isEqualTo(List.of("platform_admin"));

        assertThat(status(get("/admin/tenants"), appToken))
                .as("application token must not be accepted as platform_admin").isEqualTo(401);
        assertThat(status(get("/admin/tenants/" + TENANT + "/applications"), appToken))
                .as("application token must not be accepted by the Axiom API at all").isEqualTo(401);
    }

    // -----------------------------------------------------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------------------------------------------------

    private String tenantAdminToken() throws Exception {
        return tenantAdminToken(ADMIN_ID);
    }

    private String tenantAdminToken(String adminId) throws Exception {
        MvcResult login = mvc.perform(post("/auth/login").contentType(MediaType.APPLICATION_JSON)
                .content(json.writeValueAsString(Map.of("username", adminId, "password", PASSWORD)))).andReturn();
        assertThat(login.getResponse().getStatus()).as("tenant admin login").isEqualTo(200);
        return json.readTree(login.getResponse().getContentAsString()).get("accessToken").asText();
    }

    /** Authorization code + S256 PKCE as the logged-in tenant admin, then code redemption. */
    private String pkceToken(String clientId, String redirectUri, String scope) throws Exception {
        String verifier = Base64.getUrlEncoder().withoutPadding().encodeToString(randomBytes(48));
        String challenge = Base64.getUrlEncoder().withoutPadding().encodeToString(
                MessageDigest.getInstance("SHA-256").digest(verifier.getBytes(StandardCharsets.US_ASCII)));
        String state = UUID.randomUUID().toString();
        MvcResult authorize = mvc.perform(get("/oauth/authorize")
                .queryParam("response_type", "code").queryParam("client_id", clientId)
                .queryParam("redirect_uri", redirectUri).queryParam("scope", scope).queryParam("state", state)
                .queryParam("code_challenge", challenge).queryParam("code_challenge_method", "S256")
                .accept(MediaType.TEXT_HTML).with(user(ADMIN_ID))).andReturn();
        assertThat(authorize.getResponse().getStatus()).as("authorize redirect").isEqualTo(302);
        String location = authorize.getResponse().getHeader(HttpHeaders.LOCATION);
        assertThat(location).startsWith(redirectUri);
        var params = UriComponentsBuilder.fromUriString(location).build().getQueryParams();
        assertThat(params.getFirst("state")).isEqualTo(state);
        String code = params.getFirst("code");
        assertThat(code).as("authorization code").isNotBlank();

        MvcResult token = mvc.perform(post("/oauth/token").contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .param("grant_type", "authorization_code").param("client_id", clientId).param("code", code)
                .param("redirect_uri", redirectUri).param("code_verifier", verifier)).andReturn();
        assertThat(token.getResponse().getStatus()).as("code redemption").isEqualTo(200);
        return json.readTree(token.getResponse().getContentAsString()).get("access_token").asText();
    }

    private MvcResult send(org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder request,
                           String bearer, Object body) throws Exception {
        return mvc.perform(request.header(HttpHeaders.AUTHORIZATION, "Bearer " + bearer)
                .contentType(MediaType.APPLICATION_JSON).content(json.writeValueAsString(body))).andReturn();
    }

    private JsonNode body(MvcResult result, int expectedStatus) throws Exception {
        assertThat(result.getResponse().getStatus()).as(result.getRequest().getRequestURI())
                .isEqualTo(expectedStatus);
        return json.readTree(result.getResponse().getContentAsString());
    }

    private int status(org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder request,
                       String bearer) throws Exception {
        return mvc.perform(request.header(HttpHeaders.AUTHORIZATION, "Bearer " + bearer)).andReturn()
                .getResponse().getStatus();
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> claims(String jwt) throws Exception {
        String payload = jwt.split("\\.")[1];
        return json.readValue(Base64.getUrlDecoder().decode(payload), Map.class);
    }

    private static byte[] randomBytes(int n) {
        byte[] b = new byte[n];
        new SecureRandom().nextBytes(b);
        return b;
    }

    private static String randomKey() {
        return Base64.getEncoder().encodeToString(randomBytes(32));
    }

    private static Path tempDir() {
        try {
            return Files.createTempDirectory("esc-keys");
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }
}
