package com.openwolf.iam.invocation;

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
import org.springframework.web.util.UriComponentsBuilder;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.utility.DockerImageName;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;

/**
 * Shared fixture for the Phase 2 invocation-context ITs: one disposable PostgreSQL and Redis for the whole JVM (so the
 * outage IT can pause them), Axiom's real admin APIs, token endpoint and introspection through MockMvc, and a world
 * with two Use Cases (Claims, Wealth) whose entry callers both reach ONE shared Agent deployment.
 */
abstract class InvocationContextITSupport {
    static final String SCOPE = "ic:invoke";
    static final String EXTRA = "ic:extra";
    static final String CALLBACK = "http://127.0.0.1:9/callback";
    static final String EXCHANGE = "urn:ietf:params:oauth:grant-type:token-exchange";
    static final String ACCESS = "urn:ietf:params:oauth:token-type:access_token";
    static final String PASSWORD = UUID.randomUUID() + "-Aa1!";
    static final int MAX_DEPTH = 2;
    static final int MAX_BRANCHES = 4;
    static final int MAX_ACTIVE_PER_SESSION = 6;

    static final GenericContainer<?> POSTGRES = new GenericContainer<>(DockerImageName.parse("postgres:16"))
            .withEnv("POSTGRES_USER", "axiom").withEnv("POSTGRES_PASSWORD", "ic-isolated-test-only")
            .withEnv("POSTGRES_DB", "axiom_ic").withExposedPorts(5432)
            .withLabel("axiom.test", "phase2-invocation-context")
            .waitingFor(Wait.forLogMessage(".*database system is ready to accept connections.*", 2));
    static final GenericContainer<?> REDIS = new GenericContainer<>(DockerImageName.parse("redis:7-alpine"))
            .withExposedPorts(6379).withLabel("axiom.test", "phase2-invocation-context")
            .waitingFor(Wait.forListeningPort());
    static final Path KEY_DIR;
    static final String MASTER_KEY;

    static {
        POSTGRES.start();
        REDIS.start();
        try {
            KEY_DIR = Files.createTempDirectory("ic-keys");
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
        KEY_DIR.toFile().deleteOnExit();
        MASTER_KEY = Base64.getEncoder().encodeToString(randomBytes(32));
    }

    /** Everything the application needs; also used to start a second application context (restart proof). */
    static Map<String, Object> properties() {
        Map<String, Object> p = new LinkedHashMap<>();
        p.put("spring.datasource.url", "jdbc:postgresql://" + POSTGRES.getHost() + ":" + POSTGRES.getMappedPort(5432)
                + "/axiom_ic");
        p.put("spring.datasource.username", "axiom");
        p.put("spring.datasource.password", "ic-isolated-test-only");
        p.put("spring.datasource.hikari.connection-timeout", "3000");
        p.put("spring.datasource.hikari.data-source-properties.socketTimeout", "5");
        p.put("spring.data.redis.host", REDIS.getHost());
        p.put("spring.data.redis.port", REDIS.getMappedPort(6379));
        p.put("spring.data.redis.timeout", "3s");
        // Test-fixture opt-in: this suite's operator login still uses the legacy password-to-token endpoint, which is
        // off by default (IDP baseline secure defaults).
        p.put("iam.auth.legacy-password-login.enabled", "true");
        p.put("iam.cerbos.authz-enabled", "false");
        p.put("iam.signing-key-path", KEY_DIR.resolve("signing-key.json").toString());
        p.put("iam.signing-key-allow-generation", "true");
        p.put("iam.secrets.master-key", MASTER_KEY);
        p.put("axiom.bootstrap.enabled", "false");
        p.put("iam.oauth2.approved-business-scopes", SCOPE + "," + EXTRA);
        p.put("iam.invocation-context.max-depth", String.valueOf(MAX_DEPTH));
        p.put("iam.invocation-context.max-branches", String.valueOf(MAX_BRANCHES));
        p.put("iam.invocation-context.max-active-per-session", String.valueOf(MAX_ACTIVE_PER_SESSION));
        p.put("iam.policy-studio.base-bundle-dir",
                Path.of("..", "platform-policy", "policies").toAbsolutePath().normalize().toString());
        return p;
    }

    @DynamicPropertySource
    static void register(DynamicPropertyRegistry registry) {
        properties().forEach((k, v) -> registry.add(k, () -> v));
    }

    @Autowired MockMvc mvc;
    @Autowired JdbcTemplate jdbc;
    @Autowired PasswordEncoder passwords;
    @Autowired ActiveTenantDirectory directory;
    @Autowired ObjectMapper json;

    // =================================================================================================================
    // World: two Use Cases, one shared Agent
    // =================================================================================================================

    record Svc(String clientId, String uuid, String secret, String workloadRef, String workloadId) {}

    static final class UseCase {
        String name, appId, aud, web, routeGateway, routeAgent, role;
        Svc entry;
    }

    static final class World {
        String tenant, admin, s, agentAud, agent2Aud, siblingAud, gatewayAud, toolAud;
        Svc agent, agent2, sibling, broker;
        final Map<String, UseCase> useCases = new LinkedHashMap<>();
        UseCase uc(String name) { return useCases.get(name); }
    }

    /** One user's path into a Use Case: human token, entry delegation, Gateway authorization. */
    record Entry(String user, UseCase useCase, String p1, String p2, String p3, String rootSession) {}

    /** An established context: its token for the shared Agent and its id. */
    record Established(Entry entry, String token, String contextId, MvcResult result) {}

    void ensureTenant(String tenant, String adminId) {
        Integer exists = jdbc.queryForObject("SELECT count(*) FROM tenants WHERE id = ?", Integer.class, tenant);
        if (exists != null && exists > 0) return;
        jdbc.update("INSERT INTO tenants (id, name, slug) VALUES (?, 'Invocation context IT', ?)", tenant, tenant);
        directory.activate(tenant, "ic-test");
        jdbc.update("INSERT INTO principals (id, tenant_id, username, email, password_hash, is_active) "
                + "VALUES (?, ?, ?, ?, ?, TRUE)", adminId, tenant, adminId, adminId + "@ic.invalid", passwords.encode(PASSWORD));
        UUID role = UUID.randomUUID();
        jdbc.update("INSERT INTO roles (id, tenant_id, name) VALUES (?, ?, 'tenant_admin')", role, tenant);
        jdbc.update("INSERT INTO principal_roles (principal_id, role_id, tenant_id) VALUES (?, ?, ?)", adminId, role, tenant);
    }

    World world(String tenant) throws Exception {
        String adminId = tenant + "-admin";
        ensureTenant(tenant, adminId);
        World w = new World();
        w.tenant = tenant;
        w.s = "w" + UUID.randomUUID().toString().substring(0, 8);
        w.admin = login(adminId);
        List<String> both = List.of(SCOPE, EXTRA);
        w.agentAud = "agent:" + tenant + ":" + w.s + "-agent";
        w.agent = workload(w, app(w, "agent", w.agentAud), w.s + "-agent", both);
        w.agent2Aud = "agent:" + tenant + ":" + w.s + "-agent2";
        w.agent2 = workload(w, app(w, "agent2", w.agent2Aud), w.s + "-agent2", both);
        w.siblingAud = "agent:" + tenant + ":" + w.s + "-sibling";
        w.sibling = workload(w, app(w, "sibling", w.siblingAud), w.s + "-sibling", both);
        w.gatewayAud = "gw:" + tenant + ":" + w.s;
        w.broker = confidential(w, app(w, "gw", w.gatewayAud), w.s + "-broker", both);
        body(send(post(base(w) + "/agent-exchange/brokers"), w.admin, Map.of("oauthClientId", w.broker.clientId(),
                "gatewayAudience", w.gatewayAud, "scopes", both)), 201);
        w.toolAud = "tool:" + tenant + ":" + w.s;
        app(w, "tool", w.toolAud);
        for (String name : List.of("claims", "wealth")) {
            UseCase uc = new UseCase();
            uc.name = name;
            uc.aud = "agent:" + tenant + ":" + w.s + "-" + name;
            uc.appId = app(w, name, uc.aud);
            uc.web = w.s + "-" + name + "-web";
            body(send(post(base(w) + "/applications/" + uc.appId + "/clients"), w.admin, Map.of("clientId", uc.web,
                    "clientType", "PUBLIC_BROWSER", "redirectUris", List.of(CALLBACK), "postLogoutRedirectUris", List.of(),
                    "scopes", List.of("openid", SCOPE, EXTRA))), 201);
            uc.entry = workload(w, uc.appId, w.s + "-" + name + "-entry", both);
            uc.routeGateway = route(w, uc.entry.workloadId(), "GATEWAY", null, w.gatewayAud, both);
            uc.routeAgent = route(w, uc.entry.workloadId(), "AGENT", w.agent.workloadId(), w.agentAud, both);
            String access = base(w) + "/applications/" + uc.appId + "/access";
            uc.role = body(send(post(access + "/roles"), w.admin, Map.of("roleKey", w.s + "-" + name + "-op",
                    "displayName", "Operator", "permissions", both,
                    "permissionEffects", Map.of(SCOPE, "allow", EXTRA, "allow"))), 201).get("id").asText();
            w.useCases.put(name, uc);
        }
        route(w, w.agent.workloadId(), "GATEWAY", null, w.gatewayAud, both);
        route(w, w.agent.workloadId(), "RESOURCE", null, w.toolAud, both);
        route(w, w.agent.workloadId(), "AGENT", w.agent2.workloadId(), w.agent2Aud, both);
        route(w, w.agent2.workloadId(), "GATEWAY", null, w.gatewayAud, both);
        route(w, w.sibling.workloadId(), "GATEWAY", null, w.gatewayAud, both);
        return w;
    }

    /** A human member of one Use Case application. */
    String member(World w, String useCase) throws Exception {
        String id = w.s + "-" + useCase + "-u" + UUID.randomUUID().toString().substring(0, 4);
        jdbc.update("INSERT INTO principals (id, tenant_id, username, email, password_hash, is_active) "
                + "VALUES (?, ?, ?, ?, 'not-a-login-credential', TRUE)", id, w.tenant, id, id + "@ic.invalid");
        UseCase uc = w.uc(useCase);
        String access = base(w) + "/applications/" + uc.appId + "/access";
        String membership = body(send(post(access + "/memberships"), w.admin, Map.of("principalId", id,
                "assignmentSource", "ic-test")), 201).get("id").asText();
        body(send(post(access + "/memberships/" + membership + "/roles"), w.admin, Map.of("roleId", uc.role,
                "assignmentSource", "ic-test")), 200);
        return id;
    }

    Entry enter(World w, String useCase, String user) throws Exception {
        UseCase uc = w.uc(useCase);
        String p1 = pkce(uc.web, user);
        String p2 = token(exchange(uc.entry, p1, uc.aud, SCOPE, Map.of()));
        String p3 = token(exchange(uc.entry, p2, w.gatewayAud, SCOPE, Map.of()));
        return new Entry(user, uc, p1, p2, p3, (String) claims(p3).get("subject_sid"));
    }

    String evidence(World w, Entry e, String destination, Set<String> scopes, Instant notAfter) {
        return SyntheticInvocationAuthorizationVerifier.issue(new SyntheticInvocationAuthorizationVerifier.Statement(
                w.tenant, w.broker.clientId(), w.gatewayAud, e.user(), e.rootSession(), UUID.fromString(e.useCase().appId),
                UUID.fromString(e.useCase().entry.workloadId()), destination, scopes, notAfter,
                UUID.randomUUID().toString()));
    }

    /** Broker establishes a context for the shared Agent with verified authorization. */
    Established establish(World w, Entry e, Map<String, String> extra) throws Exception {
        Map<String, String> params = new HashMap<>();
        params.put("invocation_authorization", evidence(w, e, w.agentAud, Set.of(SCOPE), Instant.now().plusSeconds(600)));
        params.putAll(extra);
        MvcResult r = exchange(w.broker, e.p3(), w.agentAud, SCOPE, params);
        String token = token(r);
        return new Established(e, token, (String) claims(token).get("ctx"), r);
    }

    // =================================================================================================================
    // Admin API helpers
    // =================================================================================================================

    String app(World w, String kind, String audience) throws Exception {
        return body(send(post(base(w) + "/applications"), w.admin, Map.of("applicationKey", w.s + "-" + kind,
                "displayName", kind, "audience", audience)), 201).get("id").asText();
    }

    Svc confidential(World w, String appId, String clientId, List<String> scopes) throws Exception {
        JsonNode created = body(send(post(base(w) + "/applications/" + appId + "/clients"), w.admin, Map.of(
                "clientId", clientId, "clientType", "CONFIDENTIAL_SERVICE", "redirectUris", List.of(),
                "postLogoutRedirectUris", List.of(), "scopes", scopes)), 201);
        return new Svc(clientId, created.get("client").get("id").asText(), created.get("serviceSecret").asText(), null, null);
    }

    Svc workload(World w, String appId, String clientId, List<String> scopes) throws Exception {
        Svc svc = confidential(w, appId, clientId, scopes);
        String ref = "agent:" + clientId + ":test";
        String id = body(send(post(base(w) + "/ciam/agent-workloads"), w.admin, Map.of("workloadRef", ref,
                "name", clientId, "oauthClientId", clientId)), 201).get("id").asText();
        return new Svc(svc.clientId(), svc.uuid(), svc.secret(), ref, id);
    }

    String route(World w, String source, String type, String destination, String audience, List<String> scopes)
            throws Exception {
        Map<String, Object> request = new HashMap<>(Map.of("sourceWorkloadId", source, "destinationType", type,
                "audience", audience, "scopes", scopes, "purpose", "invocation context IT",
                "expiresAt", Instant.now().plusSeconds(3600).toString()));
        if (destination != null) request.put("destinationWorkloadId", destination);
        return body(send(post(base(w) + "/agent-exchange/routes"), w.admin, request), 201).get("id").asText();
    }

    static String base(World w) { return "/admin/tenants/" + w.tenant; }

    MvcResult revokeContext(World w, String contextId) throws Exception {
        return send(post(base(w) + "/invocation-contexts/" + contextId + "/revoke"), w.admin, Map.of("reason", "test"));
    }

    // =================================================================================================================
    // OAuth helpers
    // =================================================================================================================

    String pkce(String clientId, String principal) throws Exception {
        String verifier = Base64.getUrlEncoder().withoutPadding().encodeToString(randomBytes(48));
        String challenge = Base64.getUrlEncoder().withoutPadding().encodeToString(
                MessageDigest.getInstance("SHA-256").digest(verifier.getBytes(StandardCharsets.US_ASCII)));
        MvcResult authorize = mvc.perform(get("/oauth/authorize").queryParam("response_type", "code")
                .queryParam("client_id", clientId).queryParam("redirect_uri", CALLBACK)
                .queryParam("scope", "openid " + SCOPE + " " + EXTRA).queryParam("state", "st")
                .queryParam("code_challenge", challenge).queryParam("code_challenge_method", "S256")
                .accept(MediaType.TEXT_HTML).with(user(principal))).andReturn();
        assertThat(authorize.getResponse().getStatus()).as("authorize").isEqualTo(302);
        String code = UriComponentsBuilder.fromUriString(authorize.getResponse().getHeader(HttpHeaders.LOCATION))
                .build().getQueryParams().getFirst("code");
        return token(mvc.perform(post("/oauth/token").contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .param("grant_type", "authorization_code").param("client_id", clientId).param("code", code)
                .param("redirect_uri", CALLBACK).param("code_verifier", verifier)).andReturn());
    }

    MvcResult exchange(Svc requester, String subject, String audience, String scope, Map<String, String> extra)
            throws Exception {
        MockHttpServletRequestBuilder r = post("/oauth/token").contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .header(HttpHeaders.AUTHORIZATION, basic(requester)).param("grant_type", EXCHANGE)
                .param("subject_token", subject).param("subject_token_type", ACCESS)
                .param("requested_token_type", ACCESS).param("audience", audience).param("scope", scope);
        for (var e : extra.entrySet()) r = r.param(e.getKey(), e.getValue());
        return mvc.perform(r).andReturn();
    }

    JsonNode introspect(Svc caller, String token) throws Exception {
        MvcResult r = mvc.perform(post("/oauth/introspect").contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .header(HttpHeaders.AUTHORIZATION, basic(caller)).param("token", token)).andReturn();
        assertThat(r.getResponse().getStatus()).isEqualTo(200);
        return json.readTree(r.getResponse().getContentAsString());
    }

    String token(MvcResult r) throws Exception {
        assertThat(r.getResponse().getStatus()).as("token: %s", r.getResponse().getContentAsString()).isEqualTo(200);
        return json.readTree(r.getResponse().getContentAsString()).get("access_token").asText();
    }

    void denied(MvcResult r, String error) throws Exception {
        String body = r.getResponse().getContentAsString();
        assertThat(r.getResponse().getStatus()).as("denied: %s", body).isIn(400, 401);
        assertThat(body).doesNotContain("access_token");
        assertThat(json.readTree(body).path("error").asText()).as(body).isEqualTo(error);
    }

    static String basic(Svc svc) {
        return "Basic " + Base64.getEncoder().encodeToString((svc.clientId() + ":" + svc.secret())
                .getBytes(StandardCharsets.UTF_8));
    }

    String login(String adminId) throws Exception {
        MvcResult login = mvc.perform(post("/auth/login").contentType(MediaType.APPLICATION_JSON)
                .content(json.writeValueAsString(Map.of("username", adminId, "password", PASSWORD)))).andReturn();
        assertThat(login.getResponse().getStatus()).isEqualTo(200);
        return json.readTree(login.getResponse().getContentAsString()).get("accessToken").asText();
    }

    MvcResult send(MockHttpServletRequestBuilder request, String bearer, Object body) throws Exception {
        MockHttpServletRequestBuilder r = request.header(HttpHeaders.AUTHORIZATION, "Bearer " + bearer);
        if (body != null) r = r.contentType(MediaType.APPLICATION_JSON).content(json.writeValueAsString(body));
        return mvc.perform(r).andReturn();
    }

    JsonNode body(MvcResult result, int expected) throws Exception {
        assertThat(result.getResponse().getStatus()).as("%s %s -> %s", result.getRequest().getMethod(),
                result.getRequest().getRequestURI(), result.getResponse().getContentAsString()).isEqualTo(expected);
        String content = result.getResponse().getContentAsString();
        return content.isBlank() ? json.createObjectNode() : json.readTree(content);
    }

    @SuppressWarnings("unchecked")
    Map<String, Object> claims(String jwt) throws Exception {
        return json.readValue(Base64.getUrlDecoder().decode(jwt.split("\\.")[1]), Map.class);
    }

    @SuppressWarnings("unchecked")
    static Map<String, Object> act(Map<String, Object> claims) {
        return (Map<String, Object>) claims.get("act");
    }

    static long number(Map<String, Object> claims, String name) {
        return ((Number) claims.get(name)).longValue();
    }

    static List<String> scopes(Map<String, Object> claims) {
        Object scope = claims.get("scope");
        if (scope instanceof List<?> list) return list.stream().map(String::valueOf).toList();
        return scope == null ? List.of() : new ArrayList<>(List.of(String.valueOf(scope).split(" ")));
    }

    Map<String, Object> row(String contextId) {
        return jdbc.queryForMap("SELECT * FROM invocation_contexts WHERE id = ?::uuid", contextId);
    }

    static byte[] randomBytes(int n) {
        byte[] b = new byte[n];
        new SecureRandom().nextBytes(b);
        return b;
    }
}
