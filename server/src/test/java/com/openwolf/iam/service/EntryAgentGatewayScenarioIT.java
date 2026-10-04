package com.openwolf.iam.service;

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
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
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
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;

/**
 * Axiom-only scenario: distinct entry-caller, Agent-workload and Gateway-broker identities, registered through
 * Axiom's real admin APIs (as a real {@code tenant_admin}) and exercised through Axiom's real OAuth token endpoint and
 * filter chains (MockMvc), on disposable PostgreSQL and Redis containers.
 *
 * <p><b>Argus boundary.</b> The Gateway-broker → Agent/resource exchange is performed by Argus Gateway after its own
 * policy decision. This test never performs it and never simulates an Argus decision: assertions stop at Axiom's
 * actual output to the Gateway, the {@code gateway_authorization} token addressed to the broker's audience. The broker
 * identity is still registered and tested for registration exclusivity.
 *
 * <p>Isolation: containers for this class only (random localhost ports; removed by Testcontainers/Ryuk); synthetic
 * tenants {@code scn-a}/{@code scn-b}; generated passwords, secrets and keys; nothing external is contacted.
 */
@Testcontainers
@SpringBootTest(classes = IamApplication.class, webEnvironment = SpringBootTest.WebEnvironment.MOCK)
@AutoConfigureMockMvc
class EntryAgentGatewayScenarioIT {

    private static final String TENANT_A = "scn-a";
    private static final String TENANT_B = "scn-b";
    private static final String SCOPE = "scn:invoke";
    private static final String CALLBACK = "http://127.0.0.1:9/callback";
    private static final String TOKEN_EXCHANGE = "urn:ietf:params:oauth:grant-type:token-exchange";
    private static final String ACCESS_TOKEN = "urn:ietf:params:oauth:token-type:access_token";
    private static final String PASSWORD = UUID.randomUUID() + "-Aa1!";
    private static final Path KEY_DIR = tempDir();

    @Container
    static final GenericContainer<?> POSTGRES = new GenericContainer<>(DockerImageName.parse("postgres:16"))
            .withEnv("POSTGRES_USER", "axiom")
            .withEnv("POSTGRES_PASSWORD", "scn-isolated-test-only")
            .withEnv("POSTGRES_DB", "axiom_scn")
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
                + POSTGRES.getMappedPort(5432) + "/axiom_scn");
        registry.add("spring.datasource.username", () -> "axiom");
        registry.add("spring.datasource.password", () -> "scn-isolated-test-only");
        registry.add("spring.data.redis.host", REDIS::getHost);
        registry.add("spring.data.redis.port", () -> REDIS.getMappedPort(6379));
        registry.add("iam.cerbos.authz-enabled", () -> "false");
        registry.add("iam.signing-key-path", () -> KEY_DIR.resolve("signing-key.json").toString());
        registry.add("iam.signing-key-allow-generation", () -> "true");
        registry.add("iam.secrets.master-key", EntryAgentGatewayScenarioIT::randomKey);
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

    @BeforeEach
    void seedTenantsOnce() {
        if (seeded) return;
        seedTenantWithAdmin(TENANT_A, "scn-admin-a");
        seedTenantWithAdmin(TENANT_B, "scn-admin-b");
        seeded = true;
    }

    @AfterAll
    static void removeTemporaryKeyMaterial() throws Exception {
        try (var files = Files.walk(KEY_DIR)) {
            files.sorted((a, b) -> b.getNameCount() - a.getNameCount()).forEach(p -> p.toFile().delete());
        }
    }

    // =================================================================================================================
    // Supported flow
    // =================================================================================================================

    @Test
    void entryCallerAndAgentWorkloadReachTheGatewayBoundaryWithExactBindings() throws Exception {
        World w = world(TENANT_A, "scn-admin-a");

        // Human entry through the entry application's public client (S256 PKCE).
        Map<String, Object> human = claims(w.humanToken);
        assertThat(aud(human)).containsExactly(w.entryAudience);
        assertThat(human).containsEntry("tenant_id", TENANT_A).containsEntry("client_id", w.entryWebClient)
                .containsEntry("identity_kind", "workforce").containsEntry("sub", w.human);

        // Entry caller (BFF workload) exchanges the human token for its own audience: workforce delegation.
        JsonNode delegated = exchange(w.entrySvc, w.humanToken, w.entryAudience, SCOPE);
        assertThat(delegated.path("issued_token_type").asText()).isEqualTo(ACCESS_TOKEN);
        Map<String, Object> d = claims(delegated.get("access_token").asText());
        assertThat(aud(d)).containsExactly(w.entryAudience);
        assertThat(d).containsEntry("tenant_id", TENANT_A).containsEntry("sub", w.human)
                .containsEntry("client_id", w.entrySvc.clientId).containsEntry("azp", w.entrySvc.clientId)
                .containsEntry("authority_profile", "workforce").containsEntry("token_use", "exchange_subject")
                .containsEntry("subject_sid", human.get("sid"));
        assertActor(d, w.entryWorkloadRef, w.entrySvc.clientId, w.entryWorkloadId);

        // Entry caller continues to the Gateway: Axiom's output to the Argus Gateway. Assertions stop here.
        JsonNode toGateway = exchange(w.entrySvc, delegated.get("access_token").asText(), w.gatewayAudience, SCOPE);
        Map<String, Object> g = claims(toGateway.get("access_token").asText());
        assertThat(aud(g)).containsExactly(w.gatewayAudience);
        assertThat(g).containsEntry("tenant_id", TENANT_A).containsEntry("sub", w.human)
                .containsEntry("client_id", w.entrySvc.clientId)
                .containsEntry("authority_profile", "workload_continuation")
                .containsEntry("token_use", "gateway_authorization")
                .containsEntry("authority_id", w.entryToGatewayRoute)
                .containsEntry("subject_sid", human.get("sid"));
        assertActor(g, w.entryWorkloadRef, w.entrySvc.clientId, w.entryWorkloadId);
        assertThat(toGateway.path("authority_id").asText()).isEqualTo(w.entryToGatewayRoute);

        // Agent workload: its own client-credentials identity, and its autonomous continuation to the Gateway.
        String agentToken = clientCredentials(w.agentSvc, SCOPE).get("access_token").asText();
        Map<String, Object> a = claims(agentToken);
        assertThat(aud(a)).containsExactly(w.agentAudience);
        assertThat(a).containsEntry("tenant_id", TENANT_A).containsEntry("client_id", w.agentSvc.clientId)
                .containsEntry("sub", w.agentSvc.clientId).containsEntry("identity_kind", "workload")
                .doesNotContainKey("act");
        Map<String, Object> ag = claims(exchange(w.agentSvc, agentToken, w.gatewayAudience, SCOPE)
                .get("access_token").asText());
        assertThat(aud(ag)).containsExactly(w.gatewayAudience);
        assertThat(ag).containsEntry("tenant_id", TENANT_A).containsEntry("sub", w.agentSvc.clientId)
                .containsEntry("token_use", "gateway_authorization")
                .containsEntry("authority_id", w.agentToGatewayRoute);
        assertActor(ag, w.agentWorkloadRef, w.agentSvc.clientId, w.agentWorkloadId);
        // Broker identity is registered but never used here: its exchange is Argus Gateway's step.
    }

    // =================================================================================================================
    // Denials
    // =================================================================================================================

    @Test
    void brokerAndWorkloadRegistrationsCannotOverlapInEitherOrder() throws Exception {
        World w = world(TENANT_A, "scn-admin-a");
        String admin = login("scn-admin-a");
        String base = "/admin/tenants/" + TENANT_A;

        MvcResult brokerAsWorkload = send(post(base + "/ciam/agent-workloads"), admin, Map.of(
                "workloadRef", "agent:" + w.brokerSvc.clientId + ":test", "name", "overlap",
                "oauthClientId", w.brokerSvc.clientId));
        assertThat(brokerAsWorkload.getResponse().getStatus()).as("broker client as workload").isEqualTo(409);

        MvcResult workloadAsBroker = send(post(base + "/agent-exchange/brokers"), admin, Map.of(
                "oauthClientId", w.entrySvc.clientId, "gatewayAudience", w.entryAudience, "scopes", List.of(SCOPE)));
        assertThat(workloadAsBroker.getResponse().getStatus()).as("workload client as broker").isEqualTo(409);
    }

    @Test
    void humanTokenFromADifferentSourceApplicationIsRefused() throws Exception {
        World w = world(TENANT_A, "scn-admin-a");
        // The same human is also a member of an unrelated application with its own public client.
        String other = app(w.admin, TENANT_A, w.suffix + "-other", "agent:" + TENANT_A + ":" + w.suffix + "-other");
        String otherWeb = publicClient(w.admin, TENANT_A, other, w.suffix + "-other-web");
        grantMembership(w.admin, TENANT_A, other, w.human);
        String otherToken = pkce(otherWeb, w.human);

        assertDenied(exchangeRaw(w.entrySvc, otherToken, w.entryAudience, SCOPE), "invalid_grant");
    }

    @Test
    void crossTenantUseIsRefused() throws Exception {
        World a = world(TENANT_A, "scn-admin-a");
        World b = world(TENANT_B, "scn-admin-b");

        // Tenant B's entry workload cannot redeem tenant A's human token: the requester is resolved inside the subject
        // token's tenant, where B's workload client does not exist.
        assertDenied(exchangeRaw(b.entrySvc, a.humanToken, b.entryAudience, SCOPE), "unauthorized_client");
        // Nor can it carry A's delegated (exchange_subject) token on to B's Gateway.
        String aDelegated = exchange(a.entrySvc, a.humanToken, a.entryAudience, SCOPE).get("access_token").asText();
        assertDenied(exchangeRaw(b.entrySvc, aDelegated, b.gatewayAudience, SCOPE), "unauthorized_client");
        // Tenant A's admin cannot register an identity in tenant B, nor bind tenant B's client in tenant A.
        assertThat(send(post("/admin/tenants/" + TENANT_B + "/ciam/agent-workloads"), a.admin, Map.of(
                "workloadRef", "agent:cross:test", "name", "cross", "oauthClientId", b.spareSvc.clientId))
                .getResponse().getStatus()).as("A admin on B path").isEqualTo(403);
        assertThat(send(post("/admin/tenants/" + TENANT_A + "/ciam/agent-workloads"), a.admin, Map.of(
                "workloadRef", "agent:cross2:test", "name", "cross", "oauthClientId", b.spareSvc.clientId))
                .getResponse().getStatus()).as("B client registered in A").isBetween(400, 499);
    }

    @Test
    void revokedRouteRevokedWorkloadDisabledClientAndDisabledUserAreRefused() throws Exception {
        // Revoked route: no continuation to the Gateway.
        World route = world(TENANT_A, "scn-admin-a");
        String delegated = exchange(route.entrySvc, route.humanToken, route.entryAudience, SCOPE)
                .get("access_token").asText();
        assertThat(send(post("/admin/tenants/" + TENANT_A + "/agent-exchange/routes/" + route.entryToGatewayRoute
                + "/revoke"), route.admin, Map.of()).getResponse().getStatus()).isEqualTo(200);
        assertDenied(exchangeRaw(route.entrySvc, delegated, route.gatewayAudience, SCOPE), "invalid_target");

        // Revoked workload: the entry caller can no longer act.
        World workload = world(TENANT_A, "scn-admin-a");
        assertThat(send(post("/admin/tenants/" + TENANT_A + "/ciam/agent-workloads/" + workload.entryWorkloadId
                + "/revoke"), workload.admin, Map.of()).getResponse().getStatus()).isEqualTo(200);
        // The requester is no longer an active workload (AgentExchangeAuthorityService.activeWorkloadByClient).
        assertDenied(exchangeRaw(workload.entrySvc, workload.humanToken, workload.entryAudience, SCOPE), "unauthorized_client");

        // Disabled confidential client: it can no longer exchange; it fails client authentication.
        World client = world(TENANT_A, "scn-admin-a");
        disableClient(client, client.entryApp, client.entrySvc);
        assertDenied(exchangeRaw(client.entrySvc, client.humanToken, client.entryAudience, SCOPE), "invalid_client");

        // Disabled human: the existing human token can no longer be delegated.
        World human = world(TENANT_A, "scn-admin-a");
        assertThat(send(put("/users/" + human.human), human.admin, Map.of("isActive", false))
                .getResponse().getStatus()).isEqualTo(200);
        assertDenied(exchangeRaw(human.entrySvc, human.humanToken, human.entryAudience, SCOPE), "invalid_grant");
    }

    /**
     * Regression for the defect this scenario first exposed: a disabled tenant-application client used to pass OAuth
     * client authentication and fail later inside token generation ({@code IllegalStateException}, HTTP 500). It must
     * now be refused at client authentication with RFC 6749 {@code invalid_client}, and no token issued.
     */
    @Test
    void disabledConfidentialClientIsRefusedWithAnOAuthErrorNotAServerError() throws Exception {
        World w = world(TENANT_A, "scn-admin-a");
        assertThat(clientCredentialsRaw(w.agentSvc, SCOPE).getResponse().getStatus()).as("control").isEqualTo(200);
        disableClient(w, w.agentApp, w.agentSvc);

        MvcResult[] result = new MvcResult[1];
        assertThatCode(() -> result[0] = clientCredentialsRaw(w.agentSvc, SCOPE))
                .as("client_credentials for a disabled client must not escape the token endpoint as an exception")
                .doesNotThrowAnyException();
        assertThat(result[0].getResponse().getStatus()).isEqualTo(401);
        assertDenied(result[0], "invalid_client");
        // The autonomous exchange path is refused at the same boundary.
        assertDenied(exchangeRaw(w.agentSvc, "not-reached", w.gatewayAudience, SCOPE), "invalid_client");
    }

    @Test
    void disabledPublicClientCannotStartOrCompleteAuthorization() throws Exception {
        World w = world(TENANT_A, "scn-admin-a");
        // An authorization code issued while the client was active, redeemed only after it is disabled.
        Pkce pending = authorize(w.entryWebClient, w.human);
        assertThat(pending.code()).as("control: code issued while active").isNotBlank();

        disableClient(w, w.entryApp, new Svc(TENANT_A, w.entryWebClient, clientUuid(w.entryWebClient), null));

        Pkce refused = authorizeRaw(w.entryWebClient, w.human);
        // Existing contract (S256PkceEnforcementFilter): a known-but-disabled client is refused before the endpoint.
        assertThat(refused.status()).as("new authorization for a disabled client").isEqualTo(401);
        assertThat(refused.location()).as("no redirect back to the client").isNull();

        MvcResult redemption = redeem(w.entryWebClient, pending);
        assertThat(redemption.getResponse().getStatus()).isEqualTo(401);
        assertDenied(redemption, "invalid_client");
        // Tokens issued before the disable can no longer be delegated (existing exchange denial preserved).
        assertDenied(exchangeRaw(w.entrySvc, w.humanToken, w.entryAudience, SCOPE), "invalid_grant");
    }

    // =================================================================================================================
    // World: one complete, isolated identity set per call (distinct entry caller, Agent workload, Gateway broker)
    // =================================================================================================================

    private record Svc(String tenant, String clientId, String uuid, String secret) {}

    private static final class World {
        String suffix, admin, human, humanToken;
        String entryApp, agentApp, entryAudience, entryWebClient, entryWorkloadRef, entryWorkloadId;
        String agentAudience, agentWorkloadRef, agentWorkloadId;
        String gatewayAudience, entryToGatewayRoute, agentToGatewayRoute;
        Svc entrySvc, agentSvc, brokerSvc, spareSvc;
    }

    private World world(String tenant, String adminId) throws Exception {
        World w = new World();
        w.suffix = "s" + UUID.randomUUID().toString().substring(0, 8);
        w.admin = login(adminId);
        String base = "/admin/tenants/" + tenant;

        w.entryAudience = "agent:" + tenant + ":" + w.suffix + "-entry";
        w.entryApp = app(w.admin, tenant, w.suffix + "-entry", w.entryAudience);
        w.entryWebClient = publicClient(w.admin, tenant, w.entryApp, w.suffix + "-entry-web");
        w.entrySvc = confidentialClient(w.admin, tenant, w.entryApp, w.suffix + "-entry-svc");
        w.agentAudience = "agent:" + tenant + ":" + w.suffix + "-agent";
        w.agentApp = app(w.admin, tenant, w.suffix + "-agent", w.agentAudience);
        w.agentSvc = confidentialClient(w.admin, tenant, w.agentApp, w.suffix + "-agent-svc");
        w.gatewayAudience = "gw:" + tenant + ":" + w.suffix + "-gateway";
        String gatewayApp = app(w.admin, tenant, w.suffix + "-gateway", w.gatewayAudience);
        w.brokerSvc = confidentialClient(w.admin, tenant, gatewayApp, w.suffix + "-broker");
        String spareApp = app(w.admin, tenant, w.suffix + "-spare", "agent:" + tenant + ":" + w.suffix + "-spare");
        w.spareSvc = confidentialClient(w.admin, tenant, spareApp, w.suffix + "-spare-svc");

        w.entryWorkloadRef = "agent:" + w.suffix + "-entry:test";
        w.entryWorkloadId = body(send(post(base + "/ciam/agent-workloads"), w.admin, Map.of(
                "workloadRef", w.entryWorkloadRef, "name", "Entry caller", "oauthClientId", w.entrySvc.clientId)),
                201).get("id").asText();
        w.agentWorkloadRef = "agent:" + w.suffix + "-agent:test";
        w.agentWorkloadId = body(send(post(base + "/ciam/agent-workloads"), w.admin, Map.of(
                "workloadRef", w.agentWorkloadRef, "name", "Agent", "oauthClientId", w.agentSvc.clientId)),
                201).get("id").asText();
        body(send(post(base + "/agent-exchange/brokers"), w.admin, Map.of("oauthClientId", w.brokerSvc.clientId,
                "gatewayAudience", w.gatewayAudience, "scopes", List.of(SCOPE))), 201);
        w.entryToGatewayRoute = route(w.admin, tenant, w.entryWorkloadId, w.gatewayAudience);
        w.agentToGatewayRoute = route(w.admin, tenant, w.agentWorkloadId, w.gatewayAudience);

        w.human = w.suffix + "-human";
        jdbc.update("INSERT INTO principals (id, tenant_id, username, email, password_hash, is_active) "
                + "VALUES (?, ?, ?, ?, 'not-a-login-credential', TRUE)", w.human, tenant, w.human,
                w.human + "@scn.invalid");
        grantMembership(w.admin, tenant, w.entryApp, w.human);
        w.humanToken = pkce(w.entryWebClient, w.human);
        return w;
    }

    private String app(String admin, String tenant, String key, String audience) throws Exception {
        return body(send(post("/admin/tenants/" + tenant + "/applications"), admin, Map.of(
                "applicationKey", key, "displayName", key, "audience", audience)), 201).get("id").asText();
    }

    private String publicClient(String admin, String tenant, String appId, String clientId) throws Exception {
        body(send(post("/admin/tenants/" + tenant + "/applications/" + appId + "/clients"), admin, Map.of(
                "clientId", clientId, "clientType", "PUBLIC_BROWSER", "redirectUris", List.of(CALLBACK),
                "postLogoutRedirectUris", List.of(), "scopes", List.of("openid", SCOPE))), 201);
        return clientId;
    }

    private Svc confidentialClient(String admin, String tenant, String appId, String clientId) throws Exception {
        JsonNode created = body(send(post("/admin/tenants/" + tenant + "/applications/" + appId + "/clients"), admin,
                Map.of("clientId", clientId, "clientType", "CONFIDENTIAL_SERVICE", "redirectUris", List.of(),
                        "postLogoutRedirectUris", List.of(), "scopes", List.of(SCOPE))), 201);
        return new Svc(tenant, clientId, created.get("client").get("id").asText(), created.get("serviceSecret").asText());
    }

    private void disableClient(World w, String appId, Svc svc) throws Exception {
        assertThat(mvc.perform(delete("/admin/tenants/" + svc.tenant() + "/applications/" + appId + "/clients/"
                + svc.uuid()).header(HttpHeaders.AUTHORIZATION, "Bearer " + w.admin)).andReturn()
                .getResponse().getStatus()).as("disable client").isEqualTo(204);
    }

    private void grantMembership(String admin, String tenant, String appId, String principal) throws Exception {
        String base = "/admin/tenants/" + tenant + "/applications/" + appId + "/access";
        String role = body(send(post(base + "/roles"), admin, Map.of("roleKey",
                "scn-operator-" + UUID.randomUUID().toString().substring(0, 6), "displayName", "Operator",
                "permissions", List.of(SCOPE), "permissionEffects", Map.of(SCOPE, "allow"))), 201).get("id").asText();
        String membership = body(send(post(base + "/memberships"), admin, Map.of("principalId", principal,
                "assignmentSource", "scn-test")), 201).get("id").asText();
        body(send(post(base + "/memberships/" + membership + "/roles"), admin, Map.of("roleId", role,
                "assignmentSource", "scn-test")), 200);
    }

    private String route(String admin, String tenant, String sourceWorkloadId, String gatewayAudience)
            throws Exception {
        return body(send(post("/admin/tenants/" + tenant + "/agent-exchange/routes"), admin, Map.of(
                "sourceWorkloadId", sourceWorkloadId, "destinationType", "GATEWAY", "audience", gatewayAudience,
                "scopes", List.of(SCOPE), "purpose", "scenario test",
                "expiresAt", Instant.now().plusSeconds(3600).toString())), 201).get("id").asText();
    }

    // =================================================================================================================
    // OAuth helpers (real token endpoint)
    // =================================================================================================================

    private record Pkce(int status, String location, String code, String verifier) {}

    private String pkce(String clientId, String principal) throws Exception {
        Pkce issued = authorize(clientId, principal);
        MvcResult token = redeem(clientId, issued);
        assertThat(token.getResponse().getStatus()).as("code redemption").isEqualTo(200);
        return json.readTree(token.getResponse().getContentAsString()).get("access_token").asText();
    }

    private Pkce authorize(String clientId, String principal) throws Exception {
        Pkce result = authorizeRaw(clientId, principal);
        assertThat(result.status()).as("authorize").isEqualTo(302);
        assertThat(result.code()).as("authorization code").isNotBlank();
        return result;
    }

    private Pkce authorizeRaw(String clientId, String principal) throws Exception {
        String verifier = Base64.getUrlEncoder().withoutPadding().encodeToString(randomBytes(48));
        String challenge = Base64.getUrlEncoder().withoutPadding().encodeToString(
                MessageDigest.getInstance("SHA-256").digest(verifier.getBytes(StandardCharsets.US_ASCII)));
        MvcResult authorize = mvc.perform(get("/oauth/authorize").queryParam("response_type", "code")
                .queryParam("client_id", clientId).queryParam("redirect_uri", CALLBACK)
                .queryParam("scope", "openid " + SCOPE).queryParam("state", "st")
                .queryParam("code_challenge", challenge).queryParam("code_challenge_method", "S256")
                .accept(MediaType.TEXT_HTML).with(user(principal))).andReturn();
        String location = authorize.getResponse().getHeader(HttpHeaders.LOCATION);
        String code = location == null ? null
                : UriComponentsBuilder.fromUriString(location).build().getQueryParams().getFirst("code");
        return new Pkce(authorize.getResponse().getStatus(), location, code, verifier);
    }

    private MvcResult redeem(String clientId, Pkce issued) throws Exception {
        return mvc.perform(post("/oauth/token").contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .param("grant_type", "authorization_code").param("client_id", clientId).param("code", issued.code())
                .param("redirect_uri", CALLBACK).param("code_verifier", issued.verifier())).andReturn();
    }

    private String clientUuid(String clientId) {
        return jdbc.queryForObject("SELECT id::text FROM tenant_application_clients WHERE client_id = ?",
                String.class, clientId);
    }

    private MvcResult exchangeRaw(Svc requester, String subject, String audience, String scope) throws Exception {
        return mvc.perform(post("/oauth/token").contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .header(HttpHeaders.AUTHORIZATION, basic(requester))
                .param("grant_type", TOKEN_EXCHANGE).param("subject_token", subject)
                .param("subject_token_type", ACCESS_TOKEN).param("requested_token_type", ACCESS_TOKEN)
                .param("audience", audience).param("scope", scope)).andReturn();
    }

    private JsonNode exchange(Svc requester, String subject, String audience, String scope) throws Exception {
        MvcResult r = exchangeRaw(requester, subject, audience, scope);
        assertThat(r.getResponse().getStatus()).as("exchange: %s", r.getResponse().getContentAsString())
                .isEqualTo(200);
        return json.readTree(r.getResponse().getContentAsString());
    }

    private MvcResult clientCredentialsRaw(Svc client, String scope) throws Exception {
        return mvc.perform(post("/oauth/token").contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .header(HttpHeaders.AUTHORIZATION, basic(client))
                .param("grant_type", "client_credentials").param("scope", scope)).andReturn();
    }

    private JsonNode clientCredentials(Svc client, String scope) throws Exception {
        MvcResult r = clientCredentialsRaw(client, scope);
        assertThat(r.getResponse().getStatus()).as("client_credentials").isEqualTo(200);
        return json.readTree(r.getResponse().getContentAsString());
    }

    /** No token issued; status 400/401; and, when given, the exact OAuth error. */
    private void assertDenied(MvcResult result, String expectedError) throws Exception {
        String body = result.getResponse().getContentAsString();
        assertThat(result.getResponse().getStatus()).as("denied: %s", body).isIn(400, 401);
        assertThat(body).doesNotContain("access_token");
        if (expectedError != null) {
            assertThat(json.readTree(body).path("error").asText()).as(body).isEqualTo(expectedError);
        }
    }

    private static String basic(Svc svc) {
        return "Basic " + Base64.getEncoder().encodeToString(
                (svc.clientId() + ":" + svc.secret()).getBytes(StandardCharsets.UTF_8));
    }

    // =================================================================================================================
    // Generic helpers
    // =================================================================================================================

    private void seedTenantWithAdmin(String tenant, String adminId) {
        jdbc.update("INSERT INTO tenants (id, name, slug) VALUES (?, 'Scenario test', ?)", tenant, tenant);
        directory.activate(tenant, "scn-test");
        jdbc.update("INSERT INTO principals (id, tenant_id, username, email, password_hash, is_active) "
                + "VALUES (?, ?, ?, ?, ?, TRUE)", adminId, tenant, adminId, adminId + "@scn.invalid",
                passwords.encode(PASSWORD));
        UUID role = UUID.randomUUID();
        jdbc.update("INSERT INTO roles (id, tenant_id, name) VALUES (?, ?, 'tenant_admin')", role, tenant);
        jdbc.update("INSERT INTO principal_roles (principal_id, role_id, tenant_id) VALUES (?, ?, ?)",
                adminId, role, tenant);
    }

    private String login(String adminId) throws Exception {
        MvcResult login = mvc.perform(post("/auth/login").contentType(MediaType.APPLICATION_JSON)
                .content(json.writeValueAsString(Map.of("username", adminId, "password", PASSWORD)))).andReturn();
        assertThat(login.getResponse().getStatus()).as("tenant admin login").isEqualTo(200);
        return json.readTree(login.getResponse().getContentAsString()).get("accessToken").asText();
    }

    private MvcResult send(MockHttpServletRequestBuilder request, String bearer, Object body) throws Exception {
        return mvc.perform(request.header(HttpHeaders.AUTHORIZATION, "Bearer " + bearer)
                .contentType(MediaType.APPLICATION_JSON).content(json.writeValueAsString(body))).andReturn();
    }

    private JsonNode body(MvcResult result, int expected) throws Exception {
        assertThat(result.getResponse().getStatus()).as("%s %s -> %s", result.getRequest().getMethod(),
                result.getRequest().getRequestURI(), result.getResponse().getContentAsString()).isEqualTo(expected);
        return json.readTree(result.getResponse().getContentAsString());
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> claims(String jwt) throws Exception {
        return json.readValue(Base64.getUrlDecoder().decode(jwt.split("\\.")[1]), Map.class);
    }

    private static List<Object> aud(Map<String, Object> claims) {
        Object aud = claims.get("aud");
        return aud instanceof List<?> list ? List.copyOf(list) : List.of(aud);
    }

    @SuppressWarnings("unchecked")
    private static void assertActor(Map<String, Object> claims, String workloadRef, String clientId,
                                    String workloadId) {
        assertThat(claims.get("act")).as("act claim").isInstanceOf(Map.class);
        Map<String, Object> act = (Map<String, Object>) claims.get("act");
        assertThat(act).containsEntry("sub", workloadRef).containsEntry("client_id", clientId)
                .containsEntry("workload_id", workloadId);
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
            return Files.createTempDirectory("scn-keys");
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }
}
