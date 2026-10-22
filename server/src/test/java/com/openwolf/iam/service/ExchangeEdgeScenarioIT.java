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
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;

/**
 * Phase 1.1 and 1.3-1.5 scenario closure: every named Axiom exchange edge through the real token endpoint (MockMvc,
 * full filter chains) on disposable PostgreSQL and Redis.
 *
 * <pre>
 *   E1 human (PKCE) -> entry workload            workforce / exchange_subject
 *   E2 entry        -> Gateway audience  (R1)    workload_continuation / gateway_authorization
 *   E3 broker       -> Agent audience    (R2)    gateway_backend / exchange_subject
 *   E5 Agent        -> Gateway audience  (R3)    workload_continuation / gateway_authorization
 *   E4 broker       -> resource audience (R4)    gateway_backend / delegated_access
 * </pre>
 *
 * The "Gateway broker" is a confidential client registered in Axiom as the trusted broker; E3/E4 are Axiom's token
 * endpoint behaviour for that client. No Argus component, decision or fixture is involved, and nothing here claims
 * how Argus Gateway authorizes or dispatches. Cases already in {@code EntryAgentGatewayScenarioIT} (E1/E2 bindings,
 * wrong source application at E1, cross-tenant E1, revoked route/workload and disabled client/user at E1/E2,
 * broker/workload overlap) are not repeated.
 *
 * <p>Authority continuity follows the Phase 0.5 freshness contract: workload, broker and client authority is
 * re-evaluated at every exchange and introspection; entitlement removal and repeat redemption have documented bounds.
 */
@Testcontainers
@SpringBootTest(classes = IamApplication.class, webEnvironment = SpringBootTest.WebEnvironment.MOCK)
@AutoConfigureMockMvc
class ExchangeEdgeScenarioIT {

    private static final String TENANT_A = "edge-a";
    private static final String TENANT_B = "edge-b";
    private static final String SCOPE = "edge:invoke";
    private static final String EXTRA = "edge:extra";
    private static final String BOTH = SCOPE + " " + EXTRA;
    private static final String CALLBACK = "http://127.0.0.1:9/callback";
    private static final String TOKEN_EXCHANGE = "urn:ietf:params:oauth:grant-type:token-exchange";
    private static final String ACCESS_TOKEN = "urn:ietf:params:oauth:token-type:access_token";
    private static final long EXCHANGE_TTL = 300;
    private static final String PASSWORD = UUID.randomUUID() + "-Aa1!";
    private static final Path KEY_DIR = tempDir();

    @Container
    static final GenericContainer<?> POSTGRES = new GenericContainer<>(DockerImageName.parse("postgres:16"))
            .withEnv("POSTGRES_USER", "axiom").withEnv("POSTGRES_PASSWORD", "edge-isolated-test-only")
            .withEnv("POSTGRES_DB", "axiom_edge").withExposedPorts(5432)
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
                + POSTGRES.getMappedPort(5432) + "/axiom_edge");
        registry.add("spring.datasource.username", () -> "axiom");
        registry.add("spring.datasource.password", () -> "edge-isolated-test-only");
        registry.add("spring.data.redis.host", REDIS::getHost);
        registry.add("spring.data.redis.port", () -> REDIS.getMappedPort(6379));
        registry.add("iam.cerbos.authz-enabled", () -> "false");
        registry.add("iam.signing-key-path", () -> KEY_DIR.resolve("signing-key.json").toString());
        registry.add("iam.signing-key-allow-generation", () -> "true");
        registry.add("iam.secrets.master-key", () -> Base64.getEncoder().encodeToString(randomBytes(32)));
        registry.add("axiom.bootstrap.enabled", () -> "false");
        registry.add("iam.oauth2.approved-business-scopes", () -> SCOPE + "," + EXTRA);
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
    void seedOnce() {
        if (seeded) return;
        seedTenant(TENANT_A, "edge-admin-a");
        seedTenant(TENANT_B, "edge-admin-b");
        seeded = true;
    }

    @AfterAll
    static void removeKeys() throws Exception {
        try (var files = Files.walk(KEY_DIR)) {
            files.sorted((a, b) -> b.getNameCount() - a.getNameCount()).forEach(p -> p.toFile().delete());
        }
    }

    // =================================================================================================================
    // Positive chain and identity separation
    // =================================================================================================================

    @Test
    void allFiveEdgesPreserveTheHumanSubjectAndNameTheWorkloadActorNeverTheBroker() throws Exception {
        World w = world(TENANT_A, "edge-admin-a");
        Chain c = chain(w);
        Map<String, Object> human = claims(c.p1);
        String sid = (String) human.get("sid");

        Map<String, Object> p4 = claims(c.p4);
        assertThat(aud(p4)).containsExactly(w.agentAud);
        assertThat(p4).containsEntry("sub", w.human).containsEntry("subject_sid", sid)
                .containsEntry("client_id", w.broker.clientId).containsEntry("azp", w.broker.clientId)
                .containsEntry("token_use", "exchange_subject").containsEntry("authority_profile", "gateway_backend")
                .containsEntry("authority_id", w.r2).containsEntry("identity_kind", "workforce")
                .containsEntry("tenant_id", TENANT_A);
        assertActor(p4, w.entry);

        Map<String, Object> p5 = claims(c.p5);
        assertThat(aud(p5)).containsExactly(w.gatewayAud);
        assertThat(p5).containsEntry("sub", w.human).containsEntry("subject_sid", sid)
                .containsEntry("client_id", w.agent.clientId).containsEntry("azp", w.agent.clientId)
                .containsEntry("token_use", "gateway_authorization")
                .containsEntry("authority_profile", "workload_continuation").containsEntry("authority_id", w.r3);
        assertActor(p5, w.agent);

        Map<String, Object> p6 = claims(c.p6);
        assertThat(aud(p6)).containsExactly(w.toolAud);
        assertThat(p6).containsEntry("sub", w.human).containsEntry("subject_sid", sid)
                .containsEntry("client_id", w.broker.clientId).containsEntry("token_use", "delegated_access")
                .containsEntry("authority_profile", "gateway_backend").containsEntry("authority_id", w.r4);
        assertActor(p6, w.agent);

        // Every hop is a new session bound to the same human session, with a non-increasing, bounded lifetime.
        List<Map<String, Object>> hops = List.of(human, claims(c.p2), claims(c.p3), p4, p5, p6);
        Set<Object> sids = new HashSet<>();
        for (int i = 0; i < hops.size(); i++) {
            Map<String, Object> hop = hops.get(i);
            assertThat(sids.add(hop.get("sid"))).as("distinct sid at hop %d", i).isTrue();
            if (i == 0) continue;
            assertThat(number(hop, "exp")).as("exp hop %d", i).isLessThanOrEqualTo(number(hops.get(i - 1), "exp"));
            assertThat(number(hop, "exp") - number(hop, "iat")).as("lifetime hop %d", i).isLessThanOrEqualTo(EXCHANGE_TTL);
            assertThat(hop.get("sub")).isEqualTo(w.human);
        }

        // Introspection of the resource token by the resource-side caller sees it active.
        assertThat(introspect(w.broker, c.p6).path("active").asBoolean()).isTrue();
    }

    @Test
    void entryAgentAndBrokerAreDistinctRegisteredIdentities() throws Exception {
        World w = world(TENANT_A, "edge-admin-a");
        Set<String> clients = Set.of(w.entry.clientId, w.agent.clientId, w.broker.clientId);
        assertThat(clients).hasSize(3);
        JsonNode workloads = body(send(get("/admin/tenants/" + TENANT_A + "/ciam/agent-workloads"), w.admin, null), 200);
        JsonNode brokers = body(send(get("/admin/tenants/" + TENANT_A + "/agent-exchange/brokers"), w.admin, null), 200);
        Set<String> workloadClients = new HashSet<>();
        workloads.forEach(n -> workloadClients.add(n.get("oauthClientId").asText()));
        Set<String> brokerClients = new HashSet<>();
        brokers.forEach(n -> brokerClients.add(n.get("oauthClientId").asText()));
        assertThat(workloadClients).contains(w.entry.clientId, w.agent.clientId).doesNotContain(w.broker.clientId);
        assertThat(brokerClients).contains(w.broker.clientId).doesNotContain(w.entry.clientId, w.agent.clientId);
        assertThat(w.entryAud).isNotEqualTo(w.agentAud).isNotEqualTo(w.gatewayAud);
    }

    // =================================================================================================================
    // Exact redeeming client
    // =================================================================================================================

    @Test
    void onlyTheExactRedeemingClientMayAdvanceEachEdge() throws Exception {
        World w = world(TENANT_A, "edge-admin-a");
        Chain c = chain(w);
        // E2: a sibling workload of the same application, with its own Gateway route, cannot continue P2 ...
        denied(exchange(w.entrySibling, c.p2, w.gatewayAud, SCOPE), "invalid_grant");
        // ... nor can a workload of another application that also has a Gateway route (source-application binding).
        denied(exchange(w.agentSibling, c.p2, w.gatewayAud, SCOPE), "invalid_grant");
        // E5: a sibling of the Agent with its own Gateway route cannot continue P4.
        denied(exchange(w.agentSibling, c.p4, w.gatewayAud, SCOPE), "invalid_grant");
        // E3: the Gateway token is redeemable only by the broker of that Gateway audience.
        denied(exchange(w.otherBroker, c.p3, w.agentAud, SCOPE), "invalid_grant");
        denied(exchange(w.agent, c.p3, w.agentAud, SCOPE), "invalid_grant");
        denied(exchange(w.entry, c.p3, w.agentAud, SCOPE), "invalid_grant");
        // E4: the Agent's Gateway token is not redeemable by the Agent itself for the resource.
        denied(exchange(w.agent, c.p5, w.toolAud, SCOPE), "invalid_grant");
    }

    @Test
    void tokensReplayedIntoTheWrongEdgeAreRefused() throws Exception {
        World w = world(TENANT_A, "edge-admin-a");
        Chain c = chain(w);
        denied(exchange(w.broker, c.p1, w.agentAud, SCOPE), "invalid_grant");   // raw human token
        denied(exchange(w.broker, c.p2, w.agentAud, SCOPE), "invalid_grant");   // entry exchange_subject
        denied(exchange(w.broker, c.p4, w.toolAud, SCOPE), "invalid_grant");    // Agent-bound exchange_subject
        denied(exchange(w.broker, c.p6, w.toolAud, SCOPE), "invalid_grant");    // delegated_access is terminal
        denied(exchange(w.agent, c.p6, w.gatewayAud, SCOPE), "invalid_grant");
    }

    @Test
    void brokerClientCredentialsTokenIsNotAnExchangeSubject() throws Exception {
        World w = world(TENANT_A, "edge-admin-a");
        Chain c = chain(w);
        String brokerOwn = clientCredentials(w.broker, SCOPE);
        Map<String, Object> own = claims(brokerOwn);
        assertThat(aud(own)).containsExactly(w.gatewayAud);
        assertThat(own).containsEntry("identity_kind", "workload").containsEntry("sub", w.broker.clientId)
                .doesNotContainKey("act").doesNotContainKey("token_use");
        // Same audience as a gateway_authorization token, but no route authority: unusable at every edge.
        denied(exchange(w.broker, brokerOwn, w.agentAud, SCOPE), "invalid_grant");
        denied(exchange(w.agent, brokerOwn, w.gatewayAud, SCOPE), "invalid_grant");
        denied(exchange(w.entry, brokerOwn, w.gatewayAud, SCOPE), "invalid_grant");
        assertThat(c.p3).isNotEqualTo(brokerOwn);
    }

    @Test
    void autonomousAgentChainPreservesTheServiceSubjectThroughTheBroker() throws Exception {
        World w = world(TENANT_A, "edge-admin-a");
        String own = clientCredentials(w.agent, SCOPE);
        String toGateway = token(exchange(w.agent, own, w.gatewayAud, SCOPE));
        Map<String, Object> g = claims(toGateway);
        assertThat(g).containsEntry("sub", w.agent.clientId).containsEntry("identity_kind", "workload")
                .containsEntry("token_use", "gateway_authorization").containsEntry("authority_id", w.r3);
        assertActsForItself(g, w.agent);
        Map<String, Object> resource = claims(token(exchange(w.broker, toGateway, w.toolAud, SCOPE)));
        assertThat(aud(resource)).containsExactly(w.toolAud);
        assertThat(resource).containsEntry("sub", w.agent.clientId).containsEntry("identity_kind", "workload")
                .containsEntry("client_id", w.broker.clientId).containsEntry("token_use", "delegated_access")
                .containsEntry("authority_id", w.r4);
        assertActsForItself(resource, w.agent);
        assertThat(resource.get("client_id")).as("the broker redeems but is never the actor").isNotEqualTo(w.agent.clientId);
        assertThat(number(resource, "exp")).isLessThanOrEqualTo(number(g, "exp"));
        // No Agent -> Agent route, and the service token is not a broker input.
        denied(exchange(w.broker, toGateway, w.agentAud, SCOPE), "invalid_target");
        denied(exchange(w.broker, own, w.toolAud, SCOPE), "invalid_grant");
    }

    @Test
    void ambiguousRoutesToOneAudienceFailClosed() throws Exception {
        World w = world(TENANT_A, "edge-admin-a");
        Chain c = chain(w);
        // A RESOURCE route from the entry to the Agent's audience, alongside the AGENT route R2.
        route(w, w.entry.workloadId, "RESOURCE", null, w.agentAud, List.of(SCOPE), Instant.now().plusSeconds(3600));
        denied(exchange(w.broker, c.p3, w.agentAud, SCOPE), "invalid_grant");
    }

    // =================================================================================================================
    // Audience and destination
    // =================================================================================================================

    @Test
    void eachEdgeReachesOnlyItsRoutedDestination() throws Exception {
        World w = world(TENANT_A, "edge-admin-a");
        Chain c = chain(w);
        denied(exchange(w.entry, c.p1, w.gatewayAud, SCOPE), "invalid_target");       // E1 must target its own aud
        denied(exchange(w.entry, c.p2, w.agentAud, SCOPE), "invalid_target");         // skip the Gateway
        denied(exchange(w.broker, c.p3, w.gatewayAud, SCOPE), "invalid_target");      // broker never targets a Gateway
        denied(exchange(w.broker, c.p3, w.toolAud, SCOPE), "invalid_target");         // R4 belongs to the Agent
        denied(exchange(w.broker, c.p3, w.agentSiblingAud, SCOPE), "invalid_target"); // registered, but unrouted
        denied(exchange(w.agent, c.p4, w.toolAud, SCOPE), "invalid_target");          // Agent bypassing the broker
        denied(exchange(w.broker, c.p5, w.agentAud, SCOPE), "invalid_target");        // no Agent -> Agent route
    }

    // =================================================================================================================
    // Scope limits (client-, permission-, subject- and route-level)
    // =================================================================================================================

    @Test
    void scopesNarrowAtEveryEdgeAndNeverWiden() throws Exception {
        World w = world(TENANT_A, "edge-admin-a");
        String human = pkce(w.humanWeb, w.human, "openid " + BOTH);
        // IDP-04: the membership role permits only SCOPE, so the human token is narrowed at issuance and never
        // carries EXTRA even though the client is registered for it and the request asked for it.
        assertThat(scopes(claims(human))).contains(SCOPE).doesNotContain(EXTRA);
        // E1: asking the exchange for EXTRA is still refused.
        denied(exchange(w.entry, human, w.entryAud, BOTH), "invalid_scope");
        String p2 = token(exchange(w.entry, human, w.entryAud, SCOPE));
        assertThat(scopes(claims(p2))).containsExactly(SCOPE);
        // E2: R1 and the client allow EXTRA, but the subject token no longer carries it.
        denied(exchange(w.entry, p2, w.gatewayAud, BOTH), "invalid_scope");
        String p3 = token(exchange(w.entry, p2, w.gatewayAud, SCOPE));
        // E3: the broker client allows EXTRA, but R2 does not: no route matches.
        denied(exchange(w.broker, p3, w.agentAud, BOTH), "invalid_target");
        String p4 = token(exchange(w.broker, p3, w.agentAud, SCOPE));
        // E5: R3 allows EXTRA, but the subject token does not carry it.
        denied(exchange(w.agent, p4, w.gatewayAud, BOTH), "invalid_scope");
        String p5 = token(exchange(w.agent, p4, w.gatewayAud, SCOPE));
        // E4: R4 does not allow EXTRA.
        denied(exchange(w.broker, p5, w.toolAud, BOTH), "invalid_target");
        assertThat(scopes(claims(token(exchange(w.broker, p5, w.toolAud, SCOPE))))).containsExactly(SCOPE);
        // A scope no client in the chain is registered for is refused before any authority is consulted.
        denied(exchange(w.broker, p3, w.agentAud, SCOPE + " edge:unregistered"), "invalid_scope");
    }

    // =================================================================================================================
    // Tenant binding at the broker and Agent edges
    // =================================================================================================================

    @Test
    void brokerAndAgentEdgesAreTenantBound() throws Exception {
        World a = world(TENANT_A, "edge-admin-a");
        World b = world(TENANT_B, "edge-admin-b", a.gatewayAud);   // tenant B reuses A's Gateway audience string
        Chain c = chain(a);
        denied(exchange(b.broker, c.p3, a.agentAud, SCOPE), "invalid_grant");
        denied(exchange(b.agent, c.p4, a.gatewayAud, SCOPE), "unauthorized_client");
        denied(exchange(b.broker, c.p5, a.toolAud, SCOPE), "invalid_grant");
    }

    // =================================================================================================================
    // Revocation and entitlement changes after tokens were issued
    // =================================================================================================================

    @Test
    void revokedBrokerStopsEveryBrokerEdgeAndTheEntryContinuation() throws Exception {
        World w = world(TENANT_A, "edge-admin-a");
        Chain c = chain(w);
        ok(send(post(base(w) + "/agent-exchange/brokers/" + w.brokerId + "/revoke"), w.admin, Map.of()));
        denied(exchange(w.broker, c.p3, w.agentAud, SCOPE), "invalid_grant");
        denied(exchange(w.broker, c.p5, w.toolAud, SCOPE), "invalid_grant");
        denied(exchange(w.entry, c.p2, w.gatewayAud, SCOPE), "invalid_target");
        denied(exchange(w.agent, c.p4, w.gatewayAud, SCOPE), "invalid_grant");
        assertThat(introspect(w.agent, c.p6).path("active").asBoolean()).isFalse();
    }

    @Test
    void revokedRoutesStopTheirEdges() throws Exception {
        World r2 = world(TENANT_A, "edge-admin-a");
        Chain c2 = chain(r2);
        ok(send(post(base(r2) + "/agent-exchange/routes/" + r2.r2 + "/revoke"), r2.admin, Map.of()));
        denied(exchange(r2.agent, c2.p4, r2.gatewayAud, SCOPE), "invalid_grant");

        World r3 = world(TENANT_A, "edge-admin-a");
        Chain c3 = chain(r3);
        ok(send(post(base(r3) + "/agent-exchange/routes/" + r3.r3 + "/revoke"), r3.admin, Map.of()));
        denied(exchange(r3.agent, c3.p4, r3.gatewayAud, SCOPE), "invalid_target");

        World r4 = world(TENANT_A, "edge-admin-a");
        Chain c4 = chain(r4);
        ok(send(post(base(r4) + "/agent-exchange/routes/" + r4.r4 + "/revoke"), r4.admin, Map.of()));
        denied(exchange(r4.broker, c4.p5, r4.toolAud, SCOPE), "invalid_target");
        assertThat(introspect(r4.agent, c4.p6).path("active").asBoolean()).isFalse();
    }

    @Test
    void revokedAgentWorkloadAndDisabledResourceStopTheirEdges() throws Exception {
        World agent = world(TENANT_A, "edge-admin-a");
        Chain ca = chain(agent);
        ok(send(post(base(agent) + "/ciam/agent-workloads/" + agent.agent.workloadId + "/revoke"), agent.admin, Map.of()));
        denied(exchange(agent.agent, ca.p4, agent.gatewayAud, SCOPE), "invalid_grant");
        denied(exchange(agent.broker, ca.p5, agent.toolAud, SCOPE), "invalid_grant");

        World tool = world(TENANT_A, "edge-admin-a");
        Chain ct = chain(tool);
        assertThat(mvc.perform(delete(base(tool) + "/applications/" + tool.toolApp)
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + tool.admin)).andReturn().getResponse().getStatus())
                .isEqualTo(204);
        denied(exchange(tool.broker, ct.p5, tool.toolAud, SCOPE), "invalid_target");
        assertThat(introspect(tool.agent, ct.p6).path("active").asBoolean()).isFalse();
    }

    @Test
    void disabledHumanStopsTheWholeChainMidway() throws Exception {
        World w = world(TENANT_A, "edge-admin-a");
        Chain c = chain(w);
        ok(send(put("/users/" + w.human), w.admin, Map.of("isActive", false)));
        denied(exchange(w.broker, c.p3, w.agentAud, SCOPE), "invalid_grant");
        denied(exchange(w.agent, c.p4, w.gatewayAud, SCOPE), "invalid_grant");
        denied(exchange(w.broker, c.p5, w.toolAud, SCOPE), "invalid_grant");
    }

    @Test
    void lostEntitlementStopsTheEntryContinuation() throws Exception {
        World w = world(TENANT_A, "edge-admin-a");
        Chain c = chain(w);
        ok(send(delete(base(w) + "/applications/" + w.entryApp + "/access/memberships/" + w.membership
                + "/roles/" + w.role), w.admin, null));
        denied(exchange(w.entry, c.p2, w.gatewayAud, SCOPE), "invalid_grant");
    }

    @Test
    void routeExpiryBoundsIssuedTokensAndThenEndsTheEdge() throws Exception {
        World w = world(TENANT_A, "edge-admin-a");
        Instant r2Expiry = Instant.now().plusSeconds(8);
        ok(send(post(base(w) + "/agent-exchange/routes/" + w.r2 + "/revoke"), w.admin, Map.of()));
        String shortR2 = route(w, w.entry.workloadId, "AGENT", w.agent.workloadId, w.agentAud, List.of(SCOPE), r2Expiry);
        String p1 = pkce(w.humanWeb, w.human, "openid " + SCOPE);
        String p2 = token(exchange(w.entry, p1, w.entryAud, SCOPE));
        String p3 = token(exchange(w.entry, p2, w.gatewayAud, SCOPE));
        Map<String, Object> p4 = claims(token(exchange(w.broker, p3, w.agentAud, SCOPE)));
        assertThat(p4).containsEntry("authority_id", shortR2);
        assertThat(number(p4, "exp")).isLessThanOrEqualTo(r2Expiry.getEpochSecond());
        String p4Token = token(exchange(w.broker, p3, w.agentAud, SCOPE));
        Thread.sleep(Math.max(0, r2Expiry.toEpochMilli() - System.currentTimeMillis()) + 1500);
        denied(exchange(w.agent, p4Token, w.gatewayAud, SCOPE), "invalid_grant");
    }

    // =================================================================================================================
    // Authority continuity (Phase 0.5 freshness contract)
    // =================================================================================================================

    /**
     * Chosen bound: assignment removal is not revocation (Phase 1.12). It stops every new entry continuation at once;
     * tokens already derived from an earlier entry continuation stay usable only until they expire, and every token in a
     * chain expires no later than the entry-side token it came from (at most the 300-second exchange TTL after the last
     * entitlement check). Immediate cut-off of an in-flight chain is user disable or session/route/workload revocation.
     */
    @Test
    void lostEntitlementStopsNewEntryContinuationsAndBoundsTheInFlightChain() throws Exception {
        World w = world(TENANT_A, "edge-admin-a");
        Chain c = chain(w);
        long entryExpiry = number(claims(c.p2), "exp");
        assertThat(entryExpiry - number(claims(c.p2), "iat")).isLessThanOrEqualTo(EXCHANGE_TTL);
        for (String derived : List.of(c.p3, c.p4, c.p5, c.p6)) {
            assertThat(number(claims(derived), "exp")).isLessThanOrEqualTo(entryExpiry);
        }
        ok(send(delete(base(w) + "/applications/" + w.entryApp + "/access/memberships/" + w.membership
                + "/roles/" + w.role), w.admin, null));
        denied(exchange(w.entry, c.p2, w.gatewayAud, SCOPE), "invalid_grant");
        String fresh = pkce(w.humanWeb, w.human, "openid " + SCOPE);
        // The membership remains but no role grants the scope any more.
        denied(exchange(w.entry, fresh, w.entryAud, SCOPE), "invalid_scope");
        // In flight: still within the bound above, by design (not revocation).
        Map<String, Object> inFlight = claims(token(exchange(w.broker, c.p3, w.agentAud, SCOPE)));
        assertThat(number(inFlight, "exp")).isLessThanOrEqualTo(entryExpiry);
    }

    @Test
    void disabledSourceClientStopsEveryContinuationThatNamesIt() throws Exception {
        World w = world(TENANT_A, "edge-admin-a");
        Chain c = chain(w);
        disableClient(w, w.entryApp, w.entry);
        denied(exchange(w.broker, c.p3, w.agentAud, SCOPE), "invalid_grant");
        denied(exchange(w.agent, c.p4, w.gatewayAud, SCOPE), "invalid_grant");
        assertThat(introspect(w.agent, c.p4).path("active").asBoolean()).isFalse();
        // Tokens whose actor is the (still active) Agent are unaffected: P5 names only the Agent.
        assertThat(exchange(w.broker, c.p5, w.toolAud, SCOPE).getResponse().getStatus()).isEqualTo(200);
    }

    @Test
    void disabledBrokerClientInvalidatesBrokerIssuedTokens() throws Exception {
        World w = world(TENANT_A, "edge-admin-a");
        Chain c = chain(w);
        disableClient(w, w.gatewayApp, w.broker);
        denied(exchange(w.agent, c.p4, w.gatewayAud, SCOPE), "invalid_grant");
        assertThat(introspect(w.agent, c.p6).path("active").asBoolean()).isFalse();
        assertThat(exchange(w.broker, c.p3, w.agentAud, SCOPE).getResponse().getStatus()).as("client auth").isEqualTo(401);
    }

    /**
     * Chosen bound: a subject token may be redeemed more than once (retries and fan-out are legitimate). Every token
     * derived from it expires no later than the subject, carries the same root session, and dies with it.
     */
    @Test
    void repeatRedemptionIsBoundedBySubjectLifetimeAndRootSession() throws Exception {
        World w = world(TENANT_A, "edge-admin-a");
        Chain c = chain(w);
        Map<String, Object> subject = claims(c.p3);
        String again = token(exchange(w.broker, c.p3, w.agentAud, SCOPE));
        for (String derived : List.of(c.p4, again)) {
            Map<String, Object> d = claims(derived);
            assertThat(number(d, "exp")).isLessThanOrEqualTo(number(subject, "exp"));
            assertThat(d.get("subject_sid")).isEqualTo(subject.get("subject_sid"));
        }
        assertThat(claims(again).get("sid")).isNotEqualTo(claims(c.p4).get("sid"));
        ok(send(put("/users/" + w.human), w.admin, Map.of("isActive", false)));
        for (String derived : List.of(c.p4, again)) {
            denied(exchange(w.agent, derived, w.gatewayAud, SCOPE), "invalid_grant");
            assertThat(introspect(w.agent, derived).path("active").asBoolean()).isFalse();
        }
    }

    private void disableClient(World w, String appId, Svc client) throws Exception {
        assertThat(mvc.perform(delete(base(w) + "/applications/" + appId + "/clients/" + client.uuid())
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + w.admin)).andReturn().getResponse().getStatus())
                .isEqualTo(204);
    }

    // =================================================================================================================
    // World
    // =================================================================================================================

    private record Svc(String clientId, String uuid, String secret, String workloadRef, String workloadId) {}

    private static final class World {
        String tenant, admin, s, human, humanWeb, membership, role;
        String entryApp, agentApp, toolApp, gatewayApp;
        String entryAud, agentAud, gatewayAud, toolAud, agentSiblingAud;
        Svc entry, entrySibling, agent, agentSibling, broker, otherBroker;
        String brokerId, r1, r2, r3, r4;
    }

    private record Chain(String p1, String p2, String p3, String p4, String p5, String p6) {}

    private World world(String tenant, String adminId) throws Exception {
        return world(tenant, adminId, null);
    }

    private World world(String tenant, String adminId, String gatewayAudience) throws Exception {
        World w = new World();
        w.tenant = tenant;
        w.s = "e" + UUID.randomUUID().toString().substring(0, 8);
        w.admin = login(adminId);
        w.entryAud = "agent:" + tenant + ":" + w.s + "-entry";
        w.agentAud = "agent:" + tenant + ":" + w.s + "-agent";
        w.agentSiblingAud = "agent:" + tenant + ":" + w.s + "-agent2";
        w.gatewayAud = gatewayAudience != null ? gatewayAudience : "gw:" + tenant + ":" + w.s;
        w.toolAud = "tool:" + tenant + ":" + w.s;
        List<String> both = List.of(SCOPE, EXTRA);

        w.entryApp = app(w, "entry", w.entryAud);
        w.humanWeb = w.s + "-web";
        body(send(post(base(w) + "/applications/" + w.entryApp + "/clients"), w.admin, Map.of("clientId", w.humanWeb,
                "clientType", "PUBLIC_BROWSER", "redirectUris", List.of(CALLBACK), "postLogoutRedirectUris", List.of(),
                "scopes", List.of("openid", SCOPE, EXTRA))), 201);
        w.entry = workload(w, w.entryApp, w.s + "-entry", both);
        w.entrySibling = workload(w, w.entryApp, w.s + "-entry2", both);
        w.agentApp = app(w, "agent", w.agentAud);
        w.agent = workload(w, w.agentApp, w.s + "-agent", both);
        String agentSiblingApp = app(w, "agent2", w.agentSiblingAud);
        w.agentSibling = workload(w, agentSiblingApp, w.s + "-agent2", both);
        w.gatewayApp = app(w, "gw", w.gatewayAud);
        w.broker = confidential(w, w.gatewayApp, w.s + "-broker", both);
        w.brokerId = body(send(post(base(w) + "/agent-exchange/brokers"), w.admin, Map.of(
                "oauthClientId", w.broker.clientId, "gatewayAudience", w.gatewayAud, "scopes", both)), 201)
                .get("id").asText();
        String otherGatewayAud = "gw:" + tenant + ":" + w.s + "-other";
        String otherGatewayApp = app(w, "gw2", otherGatewayAud);
        w.otherBroker = confidential(w, otherGatewayApp, w.s + "-broker2", both);
        body(send(post(base(w) + "/agent-exchange/brokers"), w.admin, Map.of(
                "oauthClientId", w.otherBroker.clientId, "gatewayAudience", otherGatewayAud, "scopes", both)), 201);
        w.toolApp = app(w, "tool", w.toolAud);

        Instant hour = Instant.now().plusSeconds(3600);
        w.r1 = route(w, w.entry.workloadId, "GATEWAY", null, w.gatewayAud, both, hour);
        route(w, w.entrySibling.workloadId, "GATEWAY", null, w.gatewayAud, both, hour);
        w.r2 = route(w, w.entry.workloadId, "AGENT", w.agent.workloadId, w.agentAud, List.of(SCOPE), hour);
        w.r3 = route(w, w.agent.workloadId, "GATEWAY", null, w.gatewayAud, both, hour);
        route(w, w.agentSibling.workloadId, "GATEWAY", null, w.gatewayAud, both, hour);
        w.r4 = route(w, w.agent.workloadId, "RESOURCE", null, w.toolAud, List.of(SCOPE), hour);

        w.human = w.s + "-human";
        jdbc.update("INSERT INTO principals (id, tenant_id, username, email, password_hash, is_active) "
                + "VALUES (?, ?, ?, ?, 'not-a-login-credential', TRUE)", w.human, tenant, w.human, w.human + "@edge.invalid");
        String access = base(w) + "/applications/" + w.entryApp + "/access";
        w.role = body(send(post(access + "/roles"), w.admin, Map.of("roleKey", w.s + "-operator", "displayName", "Operator",
                "permissions", List.of(SCOPE), "permissionEffects", Map.of(SCOPE, "allow"))), 201).get("id").asText();
        w.membership = body(send(post(access + "/memberships"), w.admin, Map.of("principalId", w.human,
                "assignmentSource", "edge-test")), 201).get("id").asText();
        body(send(post(access + "/memberships/" + w.membership + "/roles"), w.admin, Map.of("roleId", w.role,
                "assignmentSource", "edge-test")), 200);
        return w;
    }

    private Chain chain(World w) throws Exception {
        String p1 = pkce(w.humanWeb, w.human, "openid " + SCOPE);
        String p2 = token(exchange(w.entry, p1, w.entryAud, SCOPE));
        String p3 = token(exchange(w.entry, p2, w.gatewayAud, SCOPE));
        String p4 = token(exchange(w.broker, p3, w.agentAud, SCOPE));
        String p5 = token(exchange(w.agent, p4, w.gatewayAud, SCOPE));
        String p6 = token(exchange(w.broker, p5, w.toolAud, SCOPE));
        return new Chain(p1, p2, p3, p4, p5, p6);
    }

    private String app(World w, String kind, String audience) throws Exception {
        return body(send(post(base(w) + "/applications"), w.admin, Map.of("applicationKey", w.s + "-" + kind,
                "displayName", kind, "audience", audience)), 201).get("id").asText();
    }

    private Svc confidential(World w, String appId, String clientId, List<String> scopes) throws Exception {
        JsonNode created = body(send(post(base(w) + "/applications/" + appId + "/clients"), w.admin, Map.of(
                "clientId", clientId, "clientType", "CONFIDENTIAL_SERVICE", "redirectUris", List.of(),
                "postLogoutRedirectUris", List.of(), "scopes", scopes)), 201);
        return new Svc(clientId, created.get("client").get("id").asText(), created.get("serviceSecret").asText(), null, null);
    }

    private Svc workload(World w, String appId, String clientId, List<String> scopes) throws Exception {
        Svc svc = confidential(w, appId, clientId, scopes);
        String ref = "agent:" + clientId + ":test";
        String id = body(send(post(base(w) + "/ciam/agent-workloads"), w.admin, Map.of("workloadRef", ref,
                "name", clientId, "oauthClientId", clientId)), 201).get("id").asText();
        return new Svc(svc.clientId(), svc.uuid(), svc.secret(), ref, id);
    }

    private String route(World w, String source, String type, String destination, String audience, List<String> scopes,
                         Instant expiresAt) throws Exception {
        Map<String, Object> request = new java.util.HashMap<>(Map.of("sourceWorkloadId", source, "destinationType", type,
                "audience", audience, "scopes", scopes, "purpose", "edge scenario", "expiresAt", expiresAt.toString()));
        if (destination != null) request.put("destinationWorkloadId", destination);
        return body(send(post(base(w) + "/agent-exchange/routes"), w.admin, request), 201).get("id").asText();
    }

    private static String base(World w) {
        return "/admin/tenants/" + w.tenant;
    }

    // =================================================================================================================
    // OAuth helpers
    // =================================================================================================================

    private String pkce(String clientId, String principal, String scope) throws Exception {
        String verifier = Base64.getUrlEncoder().withoutPadding().encodeToString(randomBytes(48));
        String challenge = Base64.getUrlEncoder().withoutPadding().encodeToString(
                MessageDigest.getInstance("SHA-256").digest(verifier.getBytes(StandardCharsets.US_ASCII)));
        MvcResult authorize = mvc.perform(get("/oauth/authorize").queryParam("response_type", "code")
                .queryParam("client_id", clientId).queryParam("redirect_uri", CALLBACK).queryParam("scope", scope)
                .queryParam("state", "st").queryParam("code_challenge", challenge)
                .queryParam("code_challenge_method", "S256").accept(MediaType.TEXT_HTML).with(user(principal))).andReturn();
        assertThat(authorize.getResponse().getStatus()).as("authorize").isEqualTo(302);
        String code = UriComponentsBuilder.fromUriString(authorize.getResponse().getHeader(HttpHeaders.LOCATION))
                .build().getQueryParams().getFirst("code");
        MvcResult redeemed = mvc.perform(post("/oauth/token").contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .param("grant_type", "authorization_code").param("client_id", clientId).param("code", code)
                .param("redirect_uri", CALLBACK).param("code_verifier", verifier)).andReturn();
        return token(redeemed);
    }

    private MvcResult exchange(Svc requester, String subject, String audience, String scope) throws Exception {
        return mvc.perform(post("/oauth/token").contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .header(HttpHeaders.AUTHORIZATION, basic(requester)).param("grant_type", TOKEN_EXCHANGE)
                .param("subject_token", subject).param("subject_token_type", ACCESS_TOKEN)
                .param("requested_token_type", ACCESS_TOKEN).param("audience", audience).param("scope", scope)).andReturn();
    }

    private String clientCredentials(Svc client, String scope) throws Exception {
        return token(mvc.perform(post("/oauth/token").contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .header(HttpHeaders.AUTHORIZATION, basic(client)).param("grant_type", "client_credentials")
                .param("scope", scope)).andReturn());
    }

    private JsonNode introspect(Svc caller, String token) throws Exception {
        MvcResult result = mvc.perform(post("/oauth/introspect").contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .header(HttpHeaders.AUTHORIZATION, basic(caller)).param("token", token)).andReturn();
        assertThat(result.getResponse().getStatus()).as("introspect").isEqualTo(200);
        return json.readTree(result.getResponse().getContentAsString());
    }

    private String token(MvcResult result) throws Exception {
        assertThat(result.getResponse().getStatus()).as("token: %s", result.getResponse().getContentAsString())
                .isEqualTo(200);
        return json.readTree(result.getResponse().getContentAsString()).get("access_token").asText();
    }

    private void denied(MvcResult result, String error) throws Exception {
        String body = result.getResponse().getContentAsString();
        assertThat(result.getResponse().getStatus()).as("denied: %s", body).isIn(400, 401);
        assertThat(body).doesNotContain("access_token");
        assertThat(json.readTree(body).path("error").asText()).as(body).isEqualTo(error);
    }

    private static String basic(Svc svc) {
        return "Basic " + Base64.getEncoder().encodeToString((svc.clientId() + ":" + svc.secret())
                .getBytes(StandardCharsets.UTF_8));
    }

    @SuppressWarnings("unchecked")
    private void assertActor(Map<String, Object> claims, Svc actor) {
        assertThat(claims.get("act")).isInstanceOf(Map.class);
        Map<String, Object> act = (Map<String, Object>) claims.get("act");
        assertThat(act).containsEntry("sub", actor.workloadRef()).containsEntry("client_id", actor.clientId())
                .containsEntry("workload_id", actor.workloadId());
        assertThat(act.get("client_id")).isNotEqualTo(claims.get("sub"));
    }

    /** An autonomous workload is both the service subject and the actor; the act claim still names it exactly. */
    @SuppressWarnings("unchecked")
    /** Standards-first (RFC 8693 section 4.1): a service acting only for itself is the subject and has no actor. */
    private void assertActsForItself(Map<String, Object> claims, Svc service) {
        assertThat(claims).doesNotContainKey("act");
        assertThat(claims.get("sub")).isEqualTo(service.clientId);
    }

    // =================================================================================================================
    // Generic helpers
    // =================================================================================================================

    private void seedTenant(String tenant, String adminId) {
        jdbc.update("INSERT INTO tenants (id, name, slug) VALUES (?, 'Edge scenario', ?)", tenant, tenant);
        directory.activate(tenant, "edge-test");
        jdbc.update("INSERT INTO principals (id, tenant_id, username, email, password_hash, is_active) "
                + "VALUES (?, ?, ?, ?, ?, TRUE)", adminId, tenant, adminId, adminId + "@edge.invalid",
                passwords.encode(PASSWORD));
        UUID role = UUID.randomUUID();
        jdbc.update("INSERT INTO roles (id, tenant_id, name) VALUES (?, ?, 'tenant_admin')", role, tenant);
        jdbc.update("INSERT INTO principal_roles (principal_id, role_id, tenant_id) VALUES (?, ?, ?)", adminId, role, tenant);
    }

    private String login(String adminId) throws Exception {
        MvcResult login = mvc.perform(post("/auth/login").contentType(MediaType.APPLICATION_JSON)
                .content(json.writeValueAsString(Map.of("username", adminId, "password", PASSWORD)))).andReturn();
        assertThat(login.getResponse().getStatus()).as("admin login").isEqualTo(200);
        return json.readTree(login.getResponse().getContentAsString()).get("accessToken").asText();
    }

    private MvcResult send(MockHttpServletRequestBuilder request, String bearer, Object body) throws Exception {
        MockHttpServletRequestBuilder r = request.header(HttpHeaders.AUTHORIZATION, "Bearer " + bearer);
        if (body != null) r = r.contentType(MediaType.APPLICATION_JSON).content(json.writeValueAsString(body));
        return mvc.perform(r).andReturn();
    }

    private void ok(MvcResult result) throws Exception {
        assertThat(result.getResponse().getStatus()).as("%s -> %s", result.getRequest().getRequestURI(),
                result.getResponse().getContentAsString()).isBetween(200, 204);
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

    private static List<String> scopes(Map<String, Object> claims) {
        Object scope = claims.get("scope");
        if (scope instanceof List<?> list) return list.stream().map(String::valueOf).toList();
        return scope == null ? List.of() : new ArrayList<>(List.of(String.valueOf(scope).split(" ")));
    }

    private static long number(Map<String, Object> claims, String name) {
        return ((Number) claims.get(name)).longValue();
    }

    private static byte[] randomBytes(int n) {
        byte[] b = new byte[n];
        new SecureRandom().nextBytes(b);
        return b;
    }

    private static Path tempDir() {
        try {
            return Files.createTempDirectory("edge-keys");
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }
}
