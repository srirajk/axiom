package com.openwolf.iam.authority;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.openwolf.iam.tenancy.ActiveTenantDirectory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.testcontainers.DockerClientFactory;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.utility.DockerImageName;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;

/**
 * Shared fixture for the Phase 3 authority ITs: one disposable PostgreSQL 16 and Redis 7 per JVM (so outage tests can
 * pause them), Axiom's real admin, CIAM, token and introspection endpoints through MockMvc, and small builders for
 * tenants, applications, clients, Agent workloads, routes and human principals.
 */
public abstract class AuthorityITSupport {
    public static final String READ = "p3:read";
    public static final String WRITE = "p3:write";
    public static final String PAY = "p3:pay";
    public static final String EXCHANGE = "urn:ietf:params:oauth:grant-type:token-exchange";
    public static final String ACCESS = "urn:ietf:params:oauth:token-type:access_token";
    public static final String PASSWORD = UUID.randomUUID() + "-Aa1!";

    public static final GenericContainer<?> POSTGRES = new GenericContainer<>(DockerImageName.parse("postgres:16"))
            .withEnv("POSTGRES_USER", "axiom").withEnv("POSTGRES_PASSWORD", "p3-isolated-test-only")
            .withEnv("POSTGRES_DB", "axiom_p3").withExposedPorts(5432)
            .withLabel("axiom.test", "phase3-authority")
            .waitingFor(Wait.forLogMessage(".*database system is ready to accept connections.*", 2));
    public static final GenericContainer<?> REDIS = new GenericContainer<>(DockerImageName.parse("redis:7-alpine"))
            .withExposedPorts(6379).withLabel("axiom.test", "phase3-authority")
            .waitingFor(Wait.forListeningPort());
    static final Path KEY_DIR;
    static final String MASTER_KEY;

    static {
        POSTGRES.start();
        REDIS.start();
        try {
            KEY_DIR = Files.createTempDirectory("p3-keys");
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
        KEY_DIR.toFile().deleteOnExit();
        MASTER_KEY = Base64.getEncoder().encodeToString(randomBytes(32));
    }

    public static Map<String, Object> properties() {
        Map<String, Object> p = new LinkedHashMap<>();
        p.put("spring.datasource.url", "jdbc:postgresql://" + POSTGRES.getHost() + ":" + POSTGRES.getMappedPort(5432)
                + "/axiom_p3");
        p.put("spring.datasource.username", "axiom");
        p.put("spring.datasource.password", "p3-isolated-test-only");
        p.put("spring.datasource.hikari.connection-timeout", "3000");
        p.put("spring.datasource.hikari.data-source-properties.socketTimeout", "5");
        p.put("spring.data.redis.host", REDIS.getHost());
        p.put("spring.data.redis.port", REDIS.getMappedPort(6379));
        p.put("spring.data.redis.timeout", "3s");
        p.put("iam.cerbos.authz-enabled", "false");
        p.put("iam.signing-key-path", KEY_DIR.resolve("signing-key.json").toString());
        p.put("iam.signing-key-allow-generation", "true");
        p.put("iam.secrets.master-key", MASTER_KEY);
        p.put("axiom.bootstrap.enabled", "false");
        p.put("iam.oauth2.approved-business-scopes", READ + "," + WRITE + "," + PAY);
        p.put("iam.ciam.delivery.worker-enabled", "false");
        p.put("iam.ciam.delivery.initial-backoff", "PT0S");
        p.put("iam.ciam.delivery.max-attempts", "3");
        p.put("iam.ciam.max-challenges-per-hour", "3");
        // Short freshness windows so stale-authentication cases are testable without long waits.
        p.put("iam.standing-grant.approval-max-auth-age", "PT5S");
        p.put("iam.client-secret-rotation.overlap", "PT5S");
        p.put("iam.policy-studio.base-bundle-dir",
                Path.of("..", "platform-policy", "policies").toAbsolutePath().normalize().toString());
        return p;
    }

    @DynamicPropertySource
    static void register(DynamicPropertyRegistry registry) {
        properties().forEach((k, v) -> registry.add(k, () -> v));
    }

    @Autowired protected MockMvc mvc;
    @Autowired protected JdbcTemplate jdbc;
    @Autowired protected PasswordEncoder passwords;
    @Autowired protected ActiveTenantDirectory directory;
    @Autowired protected ObjectMapper json;

    public record Svc(String clientId, String uuid, String secret, String audience, String appId, String workloadId,
                      String workloadRef) {}

    /** A tenant with its own administrator. */
    public static final class Tenant {
        public String id, admin, adminId, s;
    }

    protected Tenant tenant(String id) throws Exception {
        String adminId = id + "-admin";
        Integer exists = jdbc.queryForObject("SELECT count(*) FROM tenants WHERE id = ?", Integer.class, id);
        if (exists == null || exists == 0) {
            jdbc.update("INSERT INTO tenants (id, name, slug) VALUES (?, 'Phase 3 IT', ?)", id, id);
            directory.activate(id, "p3-test");
            principal(id, adminId, "tenant_admin");
        }
        Tenant t = new Tenant();
        t.id = id;
        t.adminId = adminId;
        t.s = "p" + UUID.randomUUID().toString().substring(0, 8);
        t.admin = login(adminId);
        return t;
    }

    /** A workforce principal with a real password (for /auth/login) and optionally one tenant-level role. */
    protected String principal(String tenant, String id, String role) {
        jdbc.update("INSERT INTO principals (id, tenant_id, username, email, password_hash, is_active) "
                + "VALUES (?, ?, ?, ?, ?, TRUE)", id, tenant, id, id + "@p3.invalid", passwords.encode(PASSWORD));
        if (role != null) {
            UUID existing = jdbc.query("SELECT id FROM roles WHERE tenant_id = ? AND name = ?",
                    rs -> rs.next() ? UUID.fromString(rs.getString(1)) : null, tenant, role);
            UUID roleId = existing != null ? existing : UUID.randomUUID();
            if (existing == null) jdbc.update("INSERT INTO roles (id, tenant_id, name) VALUES (?, ?, ?)", roleId, tenant, role);
            jdbc.update("INSERT INTO principal_roles (principal_id, role_id, tenant_id) VALUES (?, ?, ?)", id, roleId, tenant);
        }
        return id;
    }

    protected String app(Tenant t, String kind, String audience) throws Exception {
        return body(send(post(base(t) + "/applications"), t.admin, Map.of("applicationKey", t.s + "-" + kind,
                "displayName", kind, "audience", audience)), 201).get("id").asText();
    }

    protected Svc confidential(Tenant t, String appId, String audience, String clientId, List<String> scopes)
            throws Exception {
        JsonNode created = body(send(post(base(t) + "/applications/" + appId + "/clients"), t.admin, Map.of(
                "clientId", clientId, "clientType", "CONFIDENTIAL_SERVICE", "redirectUris", List.of(),
                "postLogoutRedirectUris", List.of(), "scopes", scopes)), 201);
        return new Svc(clientId, created.get("client").get("id").asText(), created.get("serviceSecret").asText(),
                audience, appId, null, null);
    }

    protected String browserClient(Tenant t, String appId, String clientId, List<String> scopes) throws Exception {
        body(send(post(base(t) + "/applications/" + appId + "/clients"), t.admin, Map.of("clientId", clientId,
                "clientType", "PUBLIC_BROWSER", "redirectUris", List.of("http://127.0.0.1:9/callback"),
                "postLogoutRedirectUris", List.of(), "scopes", withOpenid(scopes))), 201);
        return clientId;
    }

    private static List<String> withOpenid(List<String> scopes) {
        List<String> all = new java.util.ArrayList<>(List.of("openid"));
        all.addAll(scopes);
        return all;
    }

    /** An Agent workload: its own application/audience, confidential client and workload registration. */
    protected Svc workload(Tenant t, String name, List<String> scopes) throws Exception {
        String audience = "agent:" + t.id + ":" + t.s + "-" + name;
        String appId = app(t, name, audience);
        Svc svc = confidential(t, appId, audience, t.s + "-" + name, scopes);
        String ref = "agent:" + svc.clientId() + ":test";
        String id = body(send(post(base(t) + "/ciam/agent-workloads"), t.admin, Map.of("workloadRef", ref,
                "name", svc.clientId(), "oauthClientId", svc.clientId())), 201).get("id").asText();
        return new Svc(svc.clientId(), svc.uuid(), svc.secret(), audience, appId, id, ref);
    }

    protected String route(Tenant t, String source, String type, String destination, String audience,
                           List<String> scopes) throws Exception {
        Map<String, Object> request = new HashMap<>(Map.of("sourceWorkloadId", source, "destinationType", type,
                "audience", audience, "scopes", scopes, "purpose", "phase 3 IT",
                "expiresAt", Instant.now().plusSeconds(3600).toString()));
        if (destination != null) request.put("destinationWorkloadId", destination);
        return body(send(post(base(t) + "/agent-exchange/routes"), t.admin, request), 201).get("id").asText();
    }

    /** Grants a workforce principal the given permissions (effect allow) in an application; returns the membership. */
    protected String entitle(Tenant t, String appId, String principalId, List<String> permissions) throws Exception {
        Map<String, String> effects = new LinkedHashMap<>();
        permissions.forEach(p -> effects.put(p, "allow"));
        return entitle(t, appId, principalId, effects);
    }

    /** Membership + one role carrying exactly these permission effects (allow, read, scoped, cosign). */
    protected String entitle(Tenant t, String appId, String principalId, Map<String, String> effects) throws Exception {
        String access = base(t) + "/applications/" + appId + "/access";
        String role = body(send(post(access + "/roles"), t.admin, Map.of("roleKey", t.s + "-r" + UUID.randomUUID()
                .toString().substring(0, 6), "displayName", "Role", "permissions", List.copyOf(effects.keySet()),
                "permissionEffects", effects)), 201).get("id").asText();
        String membership = body(send(post(access + "/memberships"), t.admin, Map.of("principalId", principalId,
                "assignmentSource", "p3-test")), 201).get("id").asText();
        body(send(post(access + "/memberships/" + membership + "/roles"), t.admin, Map.of("roleId", role,
                "assignmentSource", "p3-test")), 200);
        return membership;
    }

    protected static String base(Tenant t) { return "/admin/tenants/" + t.id; }

    // =================================================================================================================
    // HTTP helpers
    // =================================================================================================================

    /** Result of an authorization-code login: tokens plus the authorization id Axiom binds the session to. */
    public record CodeLogin(String accessToken, String idToken) {}

    /** Authorization code + S256 PKCE for {@code clientId} as {@code principal} (session login simulated by MockMvc). */
    protected CodeLogin pkce(String clientId, String redirectUri, String principal, String scope) throws Exception {
        return pkce(clientId, redirectUri, org.springframework.security.test.web.servlet.request
                .SecurityMockMvcRequestPostProcessors.user(principal), scope);
    }

    /** As {@link #pkce(String, String, String, String)} with an explicit authenticated browser session. */
    protected CodeLogin pkce(String clientId, String redirectUri,
                             org.springframework.test.web.servlet.request.RequestPostProcessor session, String scope)
            throws Exception {
        String verifier = Base64.getUrlEncoder().withoutPadding().encodeToString(randomBytes(48));
        String challenge = Base64.getUrlEncoder().withoutPadding().encodeToString(
                java.security.MessageDigest.getInstance("SHA-256").digest(verifier.getBytes(StandardCharsets.US_ASCII)));
        MvcResult authorize = mvc.perform(org.springframework.test.web.servlet.request.MockMvcRequestBuilders
                .get("/oauth/authorize").queryParam("response_type", "code").queryParam("client_id", clientId)
                .queryParam("redirect_uri", redirectUri).queryParam("scope", scope).queryParam("state", "st")
                .queryParam("nonce", "n1").queryParam("code_challenge", challenge)
                .queryParam("code_challenge_method", "S256").accept(MediaType.TEXT_HTML)
                .with(session)).andReturn();
        assertThat(authorize.getResponse().getStatus()).as("authorize").isEqualTo(302);
        String code = org.springframework.web.util.UriComponentsBuilder.fromUriString(
                authorize.getResponse().getHeader(HttpHeaders.LOCATION)).build().getQueryParams().getFirst("code");
        JsonNode t = tokenResponse(mvc.perform(post("/oauth/token").contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .param("grant_type", "authorization_code").param("client_id", clientId).param("code", code)
                .param("redirect_uri", redirectUri).param("code_verifier", verifier)).andReturn());
        return new CodeLogin(t.get("access_token").asText(), t.path("id_token").asText(null));
    }

    /**
     * An Axiom API token for a workforce operator through the supported path: the Axiom Admin client's authorization
     * code + S256 PKCE flow (the legacy password-to-token endpoint is off by default since the IDP baseline).
     */
    protected String login(String principalId) throws Exception {
        // The browser session a real form login creates: the authenticated principal with the password assurance the
        // form-login filter records (auth_time/acr), exactly what the legacy endpoint asserted for a fresh login.
        var authentication = org.springframework.security.authentication.UsernamePasswordAuthenticationToken.authenticated(
                principalId, null, List.of(new org.springframework.security.core.authority.SimpleGrantedAuthority("ROLE_USER")));
        authentication.setDetails(new com.openwolf.iam.auth.AssuranceAuthenticationDetails(
                new org.springframework.mock.web.MockHttpServletRequest(), Instant.now(),
                com.openwolf.iam.auth.AuthenticationAssurance.PASSWORD));
        return pkce("axiom-admin", "http://localhost:5180/callback",
                org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors
                        .authentication(authentication), "openid profile email roles").accessToken();
    }

    protected MvcResult send(MockHttpServletRequestBuilder request, String bearer, Object body) throws Exception {
        MockHttpServletRequestBuilder r = bearer == null ? request : request.header(HttpHeaders.AUTHORIZATION, "Bearer " + bearer);
        if (body != null) r = r.contentType(MediaType.APPLICATION_JSON).content(json.writeValueAsString(body));
        return mvc.perform(r).andReturn();
    }

    protected JsonNode body(MvcResult result, int expected) throws Exception {
        assertThat(result.getResponse().getStatus()).as("%s %s -> %s %s", result.getRequest().getMethod(),
                result.getRequest().getRequestURI(), result.getResponse().getContentAsString(),
                String.valueOf(result.getResponse().getHeader(HttpHeaders.WWW_AUTHENTICATE))).isEqualTo(expected);
        String content = result.getResponse().getContentAsString();
        return content.isBlank() ? json.createObjectNode() : json.readTree(content);
    }

    protected MvcResult exchange(Svc requester, String subject, String audience, String scope,
                                 Map<String, String> extra) throws Exception {
        MockHttpServletRequestBuilder r = post("/oauth/token").contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .header(HttpHeaders.AUTHORIZATION, basic(requester)).param("grant_type", EXCHANGE)
                .param("subject_token", subject).param("subject_token_type", ACCESS)
                .param("requested_token_type", ACCESS).param("audience", audience).param("scope", scope);
        for (var e : extra.entrySet()) r = r.param(e.getKey(), e.getValue());
        return mvc.perform(r).andReturn();
    }

    protected MvcResult tokenRequest(Svc client, Map<String, String> params) throws Exception {
        MockHttpServletRequestBuilder r = post("/oauth/token").contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .header(HttpHeaders.AUTHORIZATION, basic(client));
        for (var e : params.entrySet()) r = r.param(e.getKey(), e.getValue());
        return mvc.perform(r).andReturn();
    }

    protected String clientCredentials(Svc client, String scope) throws Exception {
        return token(tokenRequest(client, Map.of("grant_type", "client_credentials", "scope", scope)));
    }

    protected JsonNode introspect(Svc caller, String token) throws Exception {
        MvcResult r = mvc.perform(post("/oauth/introspect").contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .header(HttpHeaders.AUTHORIZATION, basic(caller)).param("token", token)).andReturn();
        assertThat(r.getResponse().getStatus()).isEqualTo(200);
        return json.readTree(r.getResponse().getContentAsString());
    }

    protected String token(MvcResult r) throws Exception {
        assertThat(r.getResponse().getStatus()).as("token: %s", r.getResponse().getContentAsString()).isEqualTo(200);
        return json.readTree(r.getResponse().getContentAsString()).get("access_token").asText();
    }

    protected JsonNode tokenResponse(MvcResult r) throws Exception {
        assertThat(r.getResponse().getStatus()).as("token: %s", r.getResponse().getContentAsString()).isEqualTo(200);
        return json.readTree(r.getResponse().getContentAsString());
    }

    protected void denied(MvcResult r, String error) throws Exception {
        String body = r.getResponse().getContentAsString();
        assertThat(r.getResponse().getStatus()).as("denied: %s", body).isIn(400, 401);
        assertThat(body).doesNotContain("access_token");
        assertThat(json.readTree(body).path("error").asText()).as(body).isEqualTo(error);
    }

    protected static String basic(Svc svc) {
        return "Basic " + Base64.getEncoder().encodeToString((svc.clientId() + ":" + svc.secret())
                .getBytes(StandardCharsets.UTF_8));
    }

    @SuppressWarnings("unchecked")
    protected Map<String, Object> claims(String jwt) throws Exception {
        return json.readValue(Base64.getUrlDecoder().decode(jwt.split("\\.")[1]), Map.class);
    }

    protected String auditText(String tenant) {
        return String.join("\n", jdbc.queryForList(
                "SELECT coalesce(before_state::text,'') || coalesce(after_state::text,'') FROM audit_log WHERE tenant_id = ?",
                String.class, tenant)) + "\n" + String.join("\n", jdbc.queryForList(
                "SELECT details::text FROM ciam_lifecycle_events WHERE tenant_id = ?", String.class, tenant));
    }

    // =================================================================================================================
    // Dependency outage helpers
    // =================================================================================================================

    protected static void pause(GenericContainer<?> c) {
        DockerClientFactory.instance().client().pauseContainerCmd(c.getContainerId()).exec();
    }

    protected static void unpause(GenericContainer<?> c) {
        DockerClientFactory.instance().client().unpauseContainerCmd(c.getContainerId()).exec();
    }

    protected void awaitDatabase() throws InterruptedException {
        for (int i = 0; i < 40; i++) {
            try {
                jdbc.queryForObject("SELECT 1", Integer.class);
                return;
            } catch (RuntimeException notYet) {
                Thread.sleep(250);
            }
        }
        throw new AssertionError("database did not recover");
    }

    public interface Call { MvcResult run() throws Exception; }

    /** Fail closed = no access token, whether the endpoint answers with an error or the request aborts. */
    protected void assertNoToken(Call call) {
        try {
            MvcResult r = call.run();
            assertThat(r.getResponse().getStatus()).as(r.getResponse().getContentAsString()).isNotEqualTo(200);
            assertThat(r.getResponse().getContentAsString()).doesNotContain("access_token");
        } catch (AssertionError e) {
            throw e;
        } catch (Exception aborted) {
            // The request failed with an exception inside the filter chain: nothing was issued.
        }
    }

    /** Command-line arguments outrank application.yml, exactly like the test's dynamic properties (restart proofs). */
    protected static String[] commandLine() {
        List<String> args = new java.util.ArrayList<>(List.of("--server.port=0"));
        properties().forEach((k, v) -> args.add("--" + k + "=" + v));
        return args.toArray(String[]::new);
    }

    public interface Task<T> { T run(int i) throws Exception; }

    /** Runs {@code n} tasks released together from a barrier; returns their results in index order. */
    protected static <T> List<T> parallel(int n, Task<T> task) throws Exception {
        java.util.concurrent.ExecutorService pool = java.util.concurrent.Executors.newFixedThreadPool(n);
        java.util.concurrent.CyclicBarrier start = new java.util.concurrent.CyclicBarrier(n);
        try {
            List<java.util.concurrent.Future<T>> futures = new java.util.ArrayList<>();
            for (int i = 0; i < n; i++) {
                int index = i;
                futures.add(pool.submit(() -> {
                    start.await();
                    return task.run(index);
                }));
            }
            List<T> results = new java.util.ArrayList<>();
            for (var f : futures) results.add(f.get(120, java.util.concurrent.TimeUnit.SECONDS));
            return results;
        } finally {
            pool.shutdownNow();
        }
    }

    protected static byte[] randomBytes(int n) {
        byte[] b = new byte[n];
        new SecureRandom().nextBytes(b);
        return b;
    }
}
