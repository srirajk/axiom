package com.openwolf.iam.scenario.receiver;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.jwk.JWKSet;
import com.openwolf.iam.IamApplication;
import com.openwolf.iam.scenario.receiver.SyntheticGatewayFixture.AccessTokenVerifier;
import com.openwolf.iam.scenario.receiver.SyntheticGatewayFixture.Handler;
import com.openwolf.iam.scenario.receiver.SyntheticGatewayFixture.Policy;
import com.openwolf.iam.scenario.receiver.SyntheticGatewayFixture.RecordingDownstream;
import com.openwolf.iam.scenario.receiver.SyntheticGatewayFixture.Request;
import com.openwolf.iam.scenario.receiver.SyntheticGatewayFixture.Response;
import com.openwolf.iam.scenario.receiver.SyntheticGatewayFixture.SyntheticBff;
import com.openwolf.iam.scenario.receiver.SyntheticGatewayFixture.SyntheticGateway;
import com.openwolf.iam.scenario.receiver.SyntheticGatewayFixture.SyntheticReceiver;
import com.openwolf.iam.scenario.receiver.SyntheticGatewayFixture.TokenExchange;
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

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;

/**
 * Phase 1.9 and Axiom-side 1.10: the synthetic Gateway and receivers of {@link SyntheticGatewayFixture}, driven by real
 * Axiom tokens, keys and token exchanges (MockMvc over the full filter chains) on disposable PostgreSQL and Redis.
 *
 * <pre>
 *   browser -> SyntheticBff (human session; entry workload continues it)
 *           -> SyntheticGateway /agent  (verifies gateway_authorization, exchanges as broker)
 *           -> Agent receiver           (verifies exchange_subject from the broker; obtains its own continuation)
 *           -> SyntheticGateway /tool   (exchanges as broker)
 *           -> tool receiver            (verifies delegated_access; calls downstream with its own credential)
 *           -> RecordingDownstream
 * </pre>
 *
 * Every hop is recorded, so credential replacement and zero downstream calls are exact. The Gateway and receivers are
 * test fixtures with no Argus code; results describe Axiom's tokens against a reference receiver contract only.
 */
@Testcontainers
@SpringBootTest(classes = IamApplication.class, webEnvironment = SpringBootTest.WebEnvironment.MOCK)
@AutoConfigureMockMvc
class SyntheticGatewayReceiverScenarioIT {

    private static final String TENANT_A = "rcv-a";
    private static final String TENANT_B = "rcv-b";
    private static final String SCOPE = "rcv:invoke";
    private static final String CALLBACK = "http://127.0.0.1:9/callback";
    private static final String STUB_CREDENTIAL = "tool-downstream-" + UUID.randomUUID();
    private static final String PASSWORD = UUID.randomUUID() + "-Aa1!";
    private static final Path KEY_DIR = tempDir();

    @Container
    static final GenericContainer<?> POSTGRES = new GenericContainer<>(DockerImageName.parse("postgres:16"))
            .withEnv("POSTGRES_USER", "axiom").withEnv("POSTGRES_PASSWORD", "rcv-isolated-test-only")
            .withEnv("POSTGRES_DB", "axiom_rcv").withExposedPorts(5432)
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
                + POSTGRES.getMappedPort(5432) + "/axiom_rcv");
        registry.add("spring.datasource.username", () -> "axiom");
        registry.add("spring.datasource.password", () -> "rcv-isolated-test-only");
        registry.add("spring.data.redis.host", REDIS::getHost);
        registry.add("spring.data.redis.port", () -> REDIS.getMappedPort(6379));
        registry.add("iam.cerbos.authz-enabled", () -> "false");
        registry.add("iam.signing-key-path", () -> KEY_DIR.resolve("signing-key.json").toString());
        registry.add("iam.signing-key-allow-generation", () -> "true");
        registry.add("iam.secrets.master-key", () -> Base64.getEncoder().encodeToString(randomBytes(32)));
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
    void seedOnce() {
        if (seeded) return;
        seedTenant(TENANT_A, "rcv-admin-a");
        seedTenant(TENANT_B, "rcv-admin-b");
        seeded = true;
    }

    @AfterAll
    static void removeKeys() throws Exception {
        try (var files = Files.walk(KEY_DIR)) {
            files.sorted((a, b) -> b.getNameCount() - a.getNameCount()).forEach(p -> p.toFile().delete());
        }
    }

    // =================================================================================================================
    // Human BFF entry through Gateway, Agent and resource
    // =================================================================================================================

    @Test
    void humanBffEntryReachesTheResourceWithTheCredentialReplacedAtEveryHop() throws Exception {
        World w = world(TENANT_A, "rcv-admin-a");
        Fixture f = fixture(w);
        String human = pkce(w);

        Response result = f.bff.call(human, Request.of("/agent", "X-Request-Id", "req-1", "Cookie", "session=browser",
                "X-Authority-Id", "forged-route", "X-Subject", "attacker", "X-Act-Client-Id", w.broker.clientId,
                "X-Forwarded-Authorization", "Bearer " + human, "Forwarded", "for=evil"));

        assertThat(result.status()).isEqualTo(200);
        assertThat(f.toolDownstream.received).hasSize(1);
        Request final_ = f.toolDownstream.received.getFirst();
        assertThat(final_.headers()).containsOnlyKeys("authorization", "x-request-id");
        assertThat(final_.headers().get("authorization")).containsExactly("Bearer " + STUB_CREDENTIAL);

        // Hop by hop: a different credential each time, never the human session token, never a caller header.
        List<String> bearers = new ArrayList<>();
        for (Request hop : f.hops) {
            assertThat(hop.headers()).doesNotContainKeys("cookie", "x-authority-id", "x-subject", "x-act-client-id",
                    "x-forwarded-authorization", "forwarded");
            bearers.add(hop.headers().get("authorization").getFirst());
            assertThat(hop.headers().toString()).doesNotContain(human).doesNotContain("attacker").doesNotContain("forged");
        }
        assertThat(f.hops).hasSize(5);   // gateway/agent, agent receiver, gateway/tool, tool receiver, downstream
        assertThat(new HashSet<>(bearers)).hasSize(5);

        // The human is the subject at every receiver; the workload is the actor; the broker is only the redeemer.
        Map<String, Object> atAgent = f.agentReceiver.acceptedPrincipals.getFirst();
        Map<String, Object> atTool = f.toolReceiver.acceptedPrincipals.getFirst();
        Map<String, Object> humanClaims = claims(human);
        for (Map<String, Object> p : List.of(atAgent, atTool)) {
            assertThat(p).containsEntry("sub", w.human).containsEntry("identity_kind", "workforce")
                    .containsEntry("subject_sid", humanClaims.get("sid")).containsEntry("client_id", w.broker.clientId);
        }
        assertThat(actor(atAgent)).containsEntry("client_id", w.entry.clientId);
        assertThat(actor(atTool)).containsEntry("client_id", w.agent.clientId);
        assertThat(atAgent).containsEntry("token_use", "exchange_subject");
        assertThat(atTool).containsEntry("token_use", "delegated_access");
    }

    @Test
    void bffCannotSubstituteItsOwnServiceIdentityForTheHuman() throws Exception {
        World w = world(TENANT_A, "rcv-admin-a");
        Fixture f = fixture(w);
        String serviceToken = clientCredentials(w.entry);
        // Same Gateway, presented as the caller: no gateway_authorization, no human subject, no actor.
        Response viaGateway = f.gateway.handle(Request.of("/agent", "Authorization", "Bearer " + serviceToken));
        assertThat(viaGateway.status()).isIn(401, 403);
        // And the BFF cannot launder it as a human session through its own exchange.
        Response viaBff = f.bff.call(serviceToken, Request.of("/agent"));
        assertThat(viaBff.status()).isIn(401, 502);
        assertZeroDownstream(f);
    }

    // =================================================================================================================
    // Receiver audience and token-use checks, direct bypass
    // =================================================================================================================

    @Test
    void receiversRejectWrongAudienceAndTokenUseAndEveryDirectBypass() throws Exception {
        World w = world(TENANT_A, "rcv-admin-a");
        Fixture f = fixture(w);
        Tokens t = tokens(w);
        record Case(String name, Handler target, String token) {}
        List<Case> cases = List.of(
                new Case("human session straight to the Agent", f.agentReceiver, t.p1),
                new Case("BFF exchange_subject straight to the Agent", f.agentReceiver, t.p2),
                new Case("Gateway token at the Agent", f.agentReceiver, t.p3),
                new Case("resource token at the Agent", f.agentReceiver, t.p6),
                new Case("Agent's own service token at the Agent", f.agentReceiver, clientCredentials(w.agent)),
                new Case("Agent-bound token at the tool", f.toolReceiver, t.p4),
                new Case("Agent's Gateway token straight to the tool", f.toolReceiver, t.p5),
                new Case("Agent's service token at the tool", f.toolReceiver, clientCredentials(w.agent)),
                new Case("broker's service token at the tool", f.toolReceiver, clientCredentials(w.broker)),
                new Case("human session at the tool", f.toolReceiver, t.p1),
                new Case("Agent-bound token at the Gateway", f.gateway, t.p4),
                new Case("human session at the Gateway", f.gateway, t.p1),
                new Case("resource token at the Gateway", f.gateway, t.p6));
        for (Case c : cases) {
            Response r = c.target().handle(Request.of(c.target() == f.gateway ? "/tool" : "/x",
                    "Authorization", "Bearer " + c.token()));
            assertThat(r.status()).as(c.name()).isIn(401, 403);
        }
        assertZeroDownstream(f);
    }

    @Test
    void callerWrittenAuthorityHeadersNeverAuthorizeAnything() throws Exception {
        World w = world(TENANT_A, "rcv-admin-a");
        Fixture f = fixture(w);
        Tokens t = tokens(w);
        String[] forged = {"X-Authority-Id", w.r2, "X-Token-Use", "gateway_authorization", "X-Subject", w.human,
                "X-Act-Client-Id", w.entry.clientId, "X-Tenant-Id", TENANT_A};
        for (Handler target : List.of(f.gateway, f.agentReceiver, f.toolReceiver)) {
            assertThat(target.handle(Request.of("/agent", forged)).status()).as("headers only").isEqualTo(401);
            String[] withWrongToken = java.util.Arrays.copyOf(forged, forged.length + 2);
            withWrongToken[forged.length] = "Authorization";
            withWrongToken[forged.length + 1] = "Bearer " + t.p2;
            assertThat(target.handle(Request.of("/agent", withWrongToken)).status()).as("headers + wrong token").isIn(401, 403);
        }
        assertZeroDownstream(f);
    }

    // =================================================================================================================
    // Zero downstream calls when Axiom refuses an onward exchange
    // =================================================================================================================

    @Test
    void gatewayForwardsNothingWhenAxiomRefusesTheBrokerExchange() throws Exception {
        World w = world(TENANT_A, "rcv-admin-a");
        Fixture f = fixture(w);
        String human = pkce(w);
        ok(send(post("/admin/tenants/" + w.tenant + "/agent-exchange/routes/" + w.r2 + "/revoke"), w.admin, Map.of()));
        Response r = f.bff.call(human, Request.of("/agent"));
        assertThat(r.status()).isEqualTo(502);
        assertThat(r.error()).isEqualTo("upstream_exchange_failed:invalid_target");
        assertZeroDownstream(f);
    }

    @Test
    void agentReceiverNeverFallsBackToTheInboundTokenWhenItsOwnExchangeFails() throws Exception {
        World w = world(TENANT_A, "rcv-admin-a");
        Fixture f = fixture(w);
        String human = pkce(w);
        ok(send(post("/admin/tenants/" + w.tenant + "/agent-exchange/routes/" + w.r3 + "/revoke"), w.admin, Map.of()));
        Response r = f.bff.call(human, Request.of("/agent"));
        assertThat(r.status()).isEqualTo(502);
        assertThat(r.error()).isEqualTo("destination_credential_unavailable");
        assertThat(f.gateway.forwarded).as("only the first Gateway hop happened").isEqualTo(1);
        assertThat(f.agentReceiver.acceptedPrincipals).isEmpty();
        assertThat(f.toolReceiver.acceptedPrincipals).isEmpty();
        assertThat(f.toolDownstream.received).isEmpty();
    }

    // =================================================================================================================
    // Generic for any authorized client set
    // =================================================================================================================

    @Test
    void theSameFixtureServesAnyRegisteredClientSetAndKeepsThemApart() throws Exception {
        World a = world(TENANT_A, "rcv-admin-a");
        World b = world(TENANT_B, "rcv-admin-b");
        Fixture fa = fixture(a);
        Fixture fb = fixture(b);
        assertThat(fb.bff.call(pkce(b), Request.of("/agent")).status()).isEqualTo(200);
        assertThat(fb.toolDownstream.received).hasSize(1);
        // A's Gateway token presented to B's Gateway, and A's broker-issued token to B's Agent: refused.
        Tokens ta = tokens(a);
        assertThat(fb.gateway.handle(Request.of("/agent", "Authorization", "Bearer " + ta.p3)).status()).isIn(401, 403);
        assertThat(fb.agentReceiver.handle(Request.of("/x", "Authorization", "Bearer " + ta.p4)).status()).isIn(401, 403);
        assertThat(fb.toolDownstream.received).hasSize(1);
        assertZeroDownstream(fa);
    }

    // =================================================================================================================
    // Revocation awareness and service subjects
    // =================================================================================================================

    @Test
    void revocationAwareReceiverRejectsWhatAnOfflineReceiverStillAccepts() throws Exception {
        World w = world(TENANT_A, "rcv-admin-a");
        Fixture f = fixture(w);
        Tokens t = tokens(w);
        RecordingDownstream checkedSink = new RecordingDownstream();
        SyntheticReceiver checked = new SyntheticReceiver(f.toolVerifier, principal -> STUB_CREDENTIAL, "/downstream",
                checkedSink, token -> introspect(w.toolIntrospector, token));
        assertThat(checked.handle(Request.of("/tool", "Authorization", "Bearer " + t.p6)).status()).isEqualTo(200);
        assertThat(checkedSink.received).hasSize(1);

        ok(send(put("/users/" + w.human), w.admin, Map.of("isActive", false)));

        // Offline verification cannot learn of the revocation before expiry (Phase 0.5): documented, not a pass.
        assertThat(f.toolReceiver.handle(Request.of("/tool", "Authorization", "Bearer " + t.p6)).status()).isEqualTo(200);
        Response revoked = checked.handle(Request.of("/tool", "Authorization", "Bearer " + t.p6));
        assertThat(revoked.status()).isEqualTo(401);
        assertThat(revoked.error()).isEqualTo("inactive_token");
        assertThat(checkedSink.received).as("no downstream call after revocation").hasSize(1);
    }

    @Test
    void revocationCheckOutageFailsClosedWithZeroDownstreamCalls() throws Exception {
        World w = world(TENANT_A, "rcv-admin-a");
        Fixture f = fixture(w);
        Tokens t = tokens(w);
        RecordingDownstream sink = new RecordingDownstream();
        SyntheticReceiver checked = new SyntheticReceiver(f.toolVerifier, principal -> STUB_CREDENTIAL, "/downstream",
                sink, token -> { throw new IllegalStateException("introspection unavailable"); });
        Response r = checked.handle(Request.of("/tool", "Authorization", "Bearer " + t.p6));
        assertThat(r.status()).isEqualTo(503);
        assertThat(sink.received).isEmpty();
    }

    @Test
    void autonomousAgentReachesTheResourceAsItsOwnServiceSubject() throws Exception {
        World w = world(TENANT_A, "rcv-admin-a");
        Fixture f = fixture(w);
        String own = clientCredentials(w.agent);
        String toGateway = exchanged(w.agent, own, w.gatewayAud);
        Response r = f.gateway.handle(Request.of("/tool", "Authorization", "Bearer " + toGateway, "X-Subject", w.human));
        assertThat(r.status()).isEqualTo(200);
        assertThat(f.toolDownstream.received).hasSize(1);
        Map<String, Object> principal = f.toolReceiver.acceptedPrincipals.getFirst();
        assertThat(principal).containsEntry("sub", w.agent.clientId).containsEntry("identity_kind", "workload")
                .containsEntry("client_id", w.broker.clientId).containsEntry("token_use", "delegated_access");
        assertThat(actor(principal)).containsEntry("client_id", w.agent.clientId);
        // The service token itself is never accepted in place of the broker-issued resource token.
        assertThat(f.toolReceiver.handle(Request.of("/tool", "Authorization", "Bearer " + own)).status()).isIn(401, 403);
        assertThat(f.toolDownstream.received).hasSize(1);
    }

    private Boolean introspect(Svc caller, String token) {
        try {
            MvcResult r = mvc.perform(post("/oauth/introspect").contentType(MediaType.APPLICATION_FORM_URLENCODED)
                    .header(HttpHeaders.AUTHORIZATION, basic(caller)).param("token", token)).andReturn();
            if (r.getResponse().getStatus() != 200) throw new IllegalStateException("introspection HTTP " + r.getResponse().getStatus());
            return json.readTree(r.getResponse().getContentAsString()).path("active").asBoolean(false);
        } catch (IllegalStateException e) {
            throw e;
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    // =================================================================================================================
    // Fixture wiring (generic classes, configured from one registered client set)
    // =================================================================================================================

    private final class Fixture {
        final List<Request> hops = new ArrayList<>();
        final AtomicInteger exchanges = new AtomicInteger();
        final RecordingDownstream toolDownstream = new RecordingDownstream();
        SyntheticGateway gateway;
        SyntheticReceiver agentReceiver;
        SyntheticReceiver toolReceiver;
        AccessTokenVerifier toolVerifier;
        SyntheticBff bff;
    }

    private Fixture fixture(World w) throws Exception {
        Fixture f = new Fixture();
        JsonNode discovery = body(mvc.perform(get("/.well-known/openid-configuration")).andReturn(), 200);
        String issuer = discovery.get("issuer").asText();
        String jwksPath = URI.create(discovery.get("jwks_uri").asText()).getPath();
        JWKSet jwks = JWKSet.parse(mvc.perform(get(jwksPath)).andReturn().getResponse().getContentAsString());
        Clock clock = Clock.systemUTC();
        TokenExchange idp = (client, secret, subject, audience, scope) -> {
            f.exchanges.incrementAndGet();
            try {
                MvcResult r = mvc.perform(post("/oauth/token").contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .header(HttpHeaders.AUTHORIZATION, "Basic " + Base64.getEncoder().encodeToString(
                                (client + ":" + secret).getBytes(StandardCharsets.UTF_8)))
                        .param("grant_type", "urn:ietf:params:oauth:grant-type:token-exchange")
                        .param("subject_token", subject)
                        .param("subject_token_type", "urn:ietf:params:oauth:token-type:access_token")
                        .param("requested_token_type", "urn:ietf:params:oauth:token-type:access_token")
                        .param("audience", audience).param("scope", scope)).andReturn();
                JsonNode body = json.readTree(r.getResponse().getContentAsString());
                return new TokenExchange.Result(r.getResponse().getStatus(), body.path("access_token").asText(null),
                        body.path("error").asText(null));
            } catch (Exception e) {
                throw new IllegalStateException(e);
            }
        };
        Handler toolDownstream = record(f, f.toolDownstream);
        f.toolVerifier = new AccessTokenVerifier(new Policy(issuer, w.toolAud, w.tenant,
                Set.of(List.of("delegated_access", "gateway_backend")), Set.of(w.broker.clientId), false,
                Set.of(w.agent.clientId), SCOPE, 300, 30), jwks, clock);
        f.toolReceiver = new SyntheticReceiver(f.toolVerifier, principal -> STUB_CREDENTIAL, "/downstream", toolDownstream);
        Handler[] gatewayRef = new Handler[1];
        f.agentReceiver = new SyntheticReceiver(new AccessTokenVerifier(new Policy(issuer, w.agentAud, w.tenant,
                Set.of(List.of("exchange_subject", "gateway_backend")), Set.of(w.broker.clientId), false,
                Set.of(w.entry.clientId), SCOPE, 300, 30), jwks, clock), principal -> {
                    TokenExchange.Result own = idp.exchange(w.agent.clientId, w.agent.secret, (String) principal.get("__token"),
                            w.gatewayAud, SCOPE);
                    if (own.status() != 200) throw new IllegalStateException(own.error());
                    return own.accessToken();
                }, "/tool", request -> gatewayRef[0].handle(request));
        f.gateway = new SyntheticGateway(new AccessTokenVerifier(new Policy(issuer, w.gatewayAud, w.tenant,
                Set.of(List.of("gateway_authorization", "workload_continuation")),
                Set.of(w.entry.clientId, w.agent.clientId), true, Set.of(), SCOPE, 300, 30), jwks, clock), idp,
                w.broker.clientId, w.broker.secret, Map.of(
                "/agent", new SyntheticGateway.Destination(w.agentAud, SCOPE, record(f, f.agentReceiver)),
                "/tool", new SyntheticGateway.Destination(w.toolAud, SCOPE, record(f, f.toolReceiver))));
        gatewayRef[0] = record(f, f.gateway);
        f.bff = new SyntheticBff(idp, w.entry.clientId, w.entry.secret, w.entryAud, w.gatewayAud, SCOPE,
                record(f, f.gateway));
        return f;
    }

    private static Handler record(Fixture f, Handler next) {
        return request -> {
            f.hops.add(request);
            return next.handle(request);
        };
    }

    private void assertZeroDownstream(Fixture f) {
        assertThat(f.toolDownstream.received).as("downstream calls").isEmpty();
        assertThat(f.agentReceiver.acceptedPrincipals).isEmpty();
        assertThat(f.toolReceiver.acceptedPrincipals).isEmpty();
        assertThat(f.gateway.forwarded).as("Gateway forwards").isZero();
    }

    // =================================================================================================================
    // Registered client set (Axiom admin APIs)
    // =================================================================================================================

    private record Svc(String clientId, String secret) {}

    private static final class World {
        String tenant, admin, s, human, humanWeb, entryAud, agentAud, gatewayAud, toolAud, r2, r3;
        Svc toolIntrospector;
        Svc entry, agent, broker;
    }

    private record Tokens(String p1, String p2, String p3, String p4, String p5, String p6) {}

    private World world(String tenant, String adminId) throws Exception {
        World w = new World();
        w.tenant = tenant;
        w.s = "r" + UUID.randomUUID().toString().substring(0, 8);
        w.admin = login(adminId);
        w.entryAud = "agent:" + tenant + ":" + w.s + "-bff";
        w.agentAud = "agent:" + tenant + ":" + w.s + "-agent";
        w.gatewayAud = "gw:" + tenant + ":" + w.s;
        w.toolAud = "tool:" + tenant + ":" + w.s;
        String entryApp = app(w, "bff", w.entryAud);
        w.humanWeb = w.s + "-web";
        body(send(post(base(w) + "/applications/" + entryApp + "/clients"), w.admin, Map.of("clientId", w.humanWeb,
                "clientType", "PUBLIC_BROWSER", "redirectUris", List.of(CALLBACK), "postLogoutRedirectUris", List.of(),
                "scopes", List.of("openid", SCOPE))), 201);
        w.entry = confidential(w, entryApp, w.s + "-bff");
        String entryWorkload = workload(w, w.entry);
        String agentApp = app(w, "agent", w.agentAud);
        w.agent = confidential(w, agentApp, w.s + "-agent");
        String agentWorkload = workload(w, w.agent);
        String gatewayApp = app(w, "gw", w.gatewayAud);
        w.broker = confidential(w, gatewayApp, w.s + "-broker");
        body(send(post(base(w) + "/agent-exchange/brokers"), w.admin, Map.of("oauthClientId", w.broker.clientId,
                "gatewayAudience", w.gatewayAud, "scopes", List.of(SCOPE))), 201);
        // The resource's own confidential client, used only by a revocation-aware tool receiver to introspect.
        w.toolIntrospector = confidential(w, app(w, "tool", w.toolAud), w.s + "-tool");
        route(w, entryWorkload, "GATEWAY", null, w.gatewayAud);
        w.r2 = route(w, entryWorkload, "AGENT", agentWorkload, w.agentAud);
        w.r3 = route(w, agentWorkload, "GATEWAY", null, w.gatewayAud);
        route(w, agentWorkload, "RESOURCE", null, w.toolAud);
        w.human = w.s + "-human";
        jdbc.update("INSERT INTO principals (id, tenant_id, username, email, password_hash, is_active) "
                + "VALUES (?, ?, ?, ?, 'not-a-login-credential', TRUE)", w.human, tenant, w.human, w.human + "@rcv.invalid");
        String access = base(w) + "/applications/" + entryApp + "/access";
        String role = body(send(post(access + "/roles"), w.admin, Map.of("roleKey", w.s + "-op", "displayName", "Op",
                "permissions", List.of(SCOPE), "permissionEffects", Map.of(SCOPE, "allow"))), 201).get("id").asText();
        String membership = body(send(post(access + "/memberships"), w.admin, Map.of("principalId", w.human,
                "assignmentSource", "rcv-test")), 201).get("id").asText();
        body(send(post(access + "/memberships/" + membership + "/roles"), w.admin, Map.of("roleId", role,
                "assignmentSource", "rcv-test")), 200);
        return w;
    }

    private Tokens tokens(World w) throws Exception {
        String p1 = pkce(w);
        String p2 = exchanged(w.entry, p1, w.entryAud);
        String p3 = exchanged(w.entry, p2, w.gatewayAud);
        String p4 = exchanged(w.broker, p3, w.agentAud);
        String p5 = exchanged(w.agent, p4, w.gatewayAud);
        String p6 = exchanged(w.broker, p5, w.toolAud);
        return new Tokens(p1, p2, p3, p4, p5, p6);
    }

    private String exchanged(Svc client, String subject, String audience) throws Exception {
        MvcResult r = mvc.perform(post("/oauth/token").contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .header(HttpHeaders.AUTHORIZATION, basic(client))
                .param("grant_type", "urn:ietf:params:oauth:grant-type:token-exchange").param("subject_token", subject)
                .param("subject_token_type", "urn:ietf:params:oauth:token-type:access_token")
                .param("audience", audience).param("scope", SCOPE)).andReturn();
        return accessToken(r);
    }

    private String clientCredentials(Svc client) throws Exception {
        return accessToken(mvc.perform(post("/oauth/token").contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .header(HttpHeaders.AUTHORIZATION, basic(client)).param("grant_type", "client_credentials")
                .param("scope", SCOPE)).andReturn());
    }

    private String pkce(World w) throws Exception {
        String verifier = Base64.getUrlEncoder().withoutPadding().encodeToString(randomBytes(48));
        String challenge = Base64.getUrlEncoder().withoutPadding().encodeToString(
                MessageDigest.getInstance("SHA-256").digest(verifier.getBytes(StandardCharsets.US_ASCII)));
        MvcResult authorize = mvc.perform(get("/oauth/authorize").queryParam("response_type", "code")
                .queryParam("client_id", w.humanWeb).queryParam("redirect_uri", CALLBACK)
                .queryParam("scope", "openid " + SCOPE).queryParam("state", "st").queryParam("code_challenge", challenge)
                .queryParam("code_challenge_method", "S256").accept(MediaType.TEXT_HTML).with(user(w.human))).andReturn();
        assertThat(authorize.getResponse().getStatus()).isEqualTo(302);
        String code = UriComponentsBuilder.fromUriString(authorize.getResponse().getHeader(HttpHeaders.LOCATION))
                .build().getQueryParams().getFirst("code");
        return accessToken(mvc.perform(post("/oauth/token").contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .param("grant_type", "authorization_code").param("client_id", w.humanWeb).param("code", code)
                .param("redirect_uri", CALLBACK).param("code_verifier", verifier)).andReturn());
    }

    private String app(World w, String kind, String audience) throws Exception {
        return body(send(post(base(w) + "/applications"), w.admin, Map.of("applicationKey", w.s + "-" + kind,
                "displayName", kind, "audience", audience)), 201).get("id").asText();
    }

    private Svc confidential(World w, String appId, String clientId) throws Exception {
        JsonNode created = body(send(post(base(w) + "/applications/" + appId + "/clients"), w.admin, Map.of(
                "clientId", clientId, "clientType", "CONFIDENTIAL_SERVICE", "redirectUris", List.of(),
                "postLogoutRedirectUris", List.of(), "scopes", List.of(SCOPE))), 201);
        return new Svc(clientId, created.get("serviceSecret").asText());
    }

    private String workload(World w, Svc svc) throws Exception {
        return body(send(post(base(w) + "/ciam/agent-workloads"), w.admin, Map.of("workloadRef",
                "agent:" + svc.clientId() + ":test", "name", svc.clientId(), "oauthClientId", svc.clientId())), 201)
                .get("id").asText();
    }

    private String route(World w, String source, String type, String destination, String audience) throws Exception {
        Map<String, Object> request = new java.util.HashMap<>(Map.of("sourceWorkloadId", source, "destinationType", type,
                "audience", audience, "scopes", List.of(SCOPE), "purpose", "receiver scenario",
                "expiresAt", Instant.now().plusSeconds(3600).toString()));
        if (destination != null) request.put("destinationWorkloadId", destination);
        return body(send(post(base(w) + "/agent-exchange/routes"), w.admin, request), 201).get("id").asText();
    }

    private static String base(World w) {
        return "/admin/tenants/" + w.tenant;
    }

    // =================================================================================================================
    // Generic helpers
    // =================================================================================================================

    private void seedTenant(String tenant, String adminId) {
        jdbc.update("INSERT INTO tenants (id, name, slug) VALUES (?, 'Receiver scenario', ?)", tenant, tenant);
        directory.activate(tenant, "rcv-test");
        jdbc.update("INSERT INTO principals (id, tenant_id, username, email, password_hash, is_active) "
                + "VALUES (?, ?, ?, ?, ?, TRUE)", adminId, tenant, adminId, adminId + "@rcv.invalid", passwords.encode(PASSWORD));
        UUID role = UUID.randomUUID();
        jdbc.update("INSERT INTO roles (id, tenant_id, name) VALUES (?, ?, 'tenant_admin')", role, tenant);
        jdbc.update("INSERT INTO principal_roles (principal_id, role_id, tenant_id) VALUES (?, ?, ?)", adminId, role, tenant);
    }

    private String login(String adminId) throws Exception {
        MvcResult login = mvc.perform(post("/auth/login").contentType(MediaType.APPLICATION_JSON)
                .content(json.writeValueAsString(Map.of("username", adminId, "password", PASSWORD)))).andReturn();
        assertThat(login.getResponse().getStatus()).isEqualTo(200);
        return json.readTree(login.getResponse().getContentAsString()).get("accessToken").asText();
    }

    private MvcResult send(MockHttpServletRequestBuilder request, String bearer, Object body) throws Exception {
        return mvc.perform(request.header(HttpHeaders.AUTHORIZATION, "Bearer " + bearer)
                .contentType(MediaType.APPLICATION_JSON).content(json.writeValueAsString(body))).andReturn();
    }

    private void ok(MvcResult result) throws Exception {
        assertThat(result.getResponse().getStatus()).as(result.getResponse().getContentAsString()).isBetween(200, 204);
    }

    private JsonNode body(MvcResult result, int expected) throws Exception {
        assertThat(result.getResponse().getStatus()).as("%s -> %s", result.getRequest().getRequestURI(),
                result.getResponse().getContentAsString()).isEqualTo(expected);
        return json.readTree(result.getResponse().getContentAsString());
    }

    private String accessToken(MvcResult result) throws Exception {
        assertThat(result.getResponse().getStatus()).as(result.getResponse().getContentAsString()).isEqualTo(200);
        return json.readTree(result.getResponse().getContentAsString()).get("access_token").asText();
    }

    private static String basic(Svc svc) {
        return "Basic " + Base64.getEncoder().encodeToString((svc.clientId() + ":" + svc.secret())
                .getBytes(StandardCharsets.UTF_8));
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> claims(String jwt) throws Exception {
        return json.readValue(Base64.getUrlDecoder().decode(jwt.split("\\.")[1]), Map.class);
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> actor(Map<String, Object> principal) {
        return (Map<String, Object>) principal.get("act");
    }

    private static byte[] randomBytes(int n) {
        byte[] b = new byte[n];
        new SecureRandom().nextBytes(b);
        return b;
    }

    private static Path tempDir() {
        try {
            return Files.createTempDirectory("rcv-keys");
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }
}
