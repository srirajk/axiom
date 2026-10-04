package com.openwolf.iam.invocation;

import com.openwolf.iam.IamApplication;
import org.junit.jupiter.api.Test;
import org.springframework.boot.WebApplicationType;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.context.annotation.Import;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import java.time.Instant;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;

/** Gate B — Phase 2.2 establishment through verified authorization and 2.3 authoritative persistence. */
@SpringBootTest(classes = IamApplication.class, webEnvironment = SpringBootTest.WebEnvironment.MOCK)
@AutoConfigureMockMvc
@Import(SyntheticInvocationAuthorizationVerifier.Config.class)
class InvocationContextEstablishmentIT extends InvocationContextITSupport {

    @Test
    void verifiedAuthorizationEstablishesAContextAndPersistsOnlyAuthoritativeState() throws Exception {
        World w = world("icb-a");
        Entry e = enter(w, "claims", member(w, "claims"));
        String evidence = evidence(w, e, w.agentAud, Set.of(SCOPE), Instant.now().plusSeconds(600));
        MvcResult r = exchange(w.broker, e.p3(), w.agentAud, SCOPE, Map.of("invocation_authorization", evidence,
                "invocation_run", "run-claims-1"));
        String token = token(r);
        Map<String, Object> c = claims(token);
        assertThat(c).containsEntry("sub", e.user()).containsEntry("ctx_ver", 1).containsEntry("ctx_depth", 0)
                .containsEntry("token_use", "exchange_subject").containsKey("jti");
        assertThat(act(c)).containsEntry("client_id", e.useCase().entry.clientId());
        String ctx = (String) c.get("ctx");
        assertThat(json.readTree(r.getResponse().getContentAsString()).get("invocation_context").asText()).isEqualTo(ctx);

        Map<String, Object> row = row(ctx);
        assertThat(row).containsEntry("tenant_id", w.tenant).containsEntry("security_scope", w.gatewayAud)
                .containsEntry("originating_subject", e.user()).containsEntry("root_session_id", e.rootSession())
                .containsEntry("broker_client_id", w.broker.clientId()).containsEntry("status", "ACTIVE")
                .containsEntry("version", 1L).containsEntry("run_ref", "run-claims-1").containsEntry("depth", 0);
        assertThat(row.get("use_case_application_id").toString()).isEqualTo(e.useCase().appId);
        assertThat(row.get("authorization_reference").toString()).startsWith("synthetic:");
        assertThat(row.get("evidence_digest").toString()).matches("[0-9a-f]{64}");
        assertThat(row.values().toString()).doesNotContain(evidence).doesNotContain(token);
        assertThat(number(c, "exp")).isLessThanOrEqualTo(((java.sql.Timestamp) row.get("deadline")).toInstant().getEpochSecond());
        assertThat(jdbc.queryForObject("SELECT count(*) FROM audit_log WHERE action = 'INVOCATION_CONTEXT_ESTABLISHED' "
                + "AND resource_id = ?", Integer.class, ctx)).isEqualTo(1);
    }

    @Test
    void unverifiedCallerWrittenReboundOrReusedAuthorizationCannotEstablish() throws Exception {
        World w = world("icb-a");
        Entry claims = enter(w, "claims", member(w, "claims"));
        Entry other = enter(w, "claims", member(w, "claims"));
        Instant later = Instant.now().plusSeconds(600);
        String good = evidence(w, claims, w.agentAud, Set.of(SCOPE), later);
        String forged = good.substring(0, good.lastIndexOf('.') + 1) + "AAAA";
        String foreignKey = SyntheticInvocationAuthorizationVerifier.issue(new SyntheticInvocationAuthorizationVerifier.Statement(
                w.tenant, w.broker.clientId(), w.gatewayAud, claims.user(), claims.rootSession(),
                java.util.UUID.fromString(claims.useCase().appId), java.util.UUID.fromString(claims.useCase().entry.workloadId()),
                w.agentAud, Set.of(SCOPE), later, "n"), "some-other-signer-key-not-trusted-by-axiom".getBytes());
        // signature forged / signed by an untrusted key
        denied(exchange(w.broker, claims.p3(), w.agentAud, SCOPE, Map.of("invocation_authorization", forged)), "invalid_grant");
        denied(exchange(w.broker, claims.p3(), w.agentAud, SCOPE, Map.of("invocation_authorization", foreignKey)), "invalid_grant");
        // evidence for another subject, destination or narrower scope cannot be reused here
        denied(exchange(w.broker, other.p3(), w.agentAud, SCOPE, Map.of("invocation_authorization", good)), "invalid_grant");
        denied(exchange(w.broker, claims.p3(), w.agentAud, SCOPE, Map.of("invocation_authorization",
                evidence(w, claims, w.agent2Aud, Set.of(SCOPE), later))), "invalid_grant");
        // widened scope: refused by the subject-scope check before any context is considered
        denied(exchange(w.broker, claims.p3(), w.agentAud, SCOPE + " " + EXTRA, Map.of("invocation_authorization", good)),
                "invalid_scope");
        // expired authorization
        denied(exchange(w.broker, claims.p3(), w.agentAud, SCOPE, Map.of("invocation_authorization",
                evidence(w, claims, w.agentAud, Set.of(SCOPE), Instant.now().minusSeconds(1)))), "invalid_grant");
        // a run label, TTL or idempotency key alone is not authority
        denied(exchange(w.broker, claims.p3(), w.agentAud, SCOPE, Map.of("invocation_run", "caller-says-so")), "invalid_request");
        // evidence is single-use: the second establishment with it fails
        token(exchange(w.broker, claims.p3(), w.agentAud, SCOPE, Map.of("invocation_authorization", good)));
        denied(exchange(w.broker, claims.p3(), w.agentAud, SCOPE, Map.of("invocation_authorization", good)), "invalid_grant");
        // only the broker on the Gateway edge may establish
        denied(exchange(claims.useCase().entry, claims.p2(), w.gatewayAud, SCOPE, Map.of("invocation_authorization",
                evidence(w, claims, w.gatewayAud, Set.of(SCOPE), later))), "invalid_request");
        // broker authentication without evidence keeps the Phase 1 behaviour and creates no context
        Map<String, Object> plain = claims(token(exchange(w.broker, claims.p3(), w.agentAud, SCOPE, Map.of())));
        assertThat(plain).doesNotContainKey("ctx");
        assertThat(jdbc.queryForObject("SELECT count(*) FROM invocation_contexts WHERE originating_subject = ?",
                Integer.class, claims.user())).isEqualTo(1);
        assertThat(jdbc.queryForObject("SELECT count(*) FROM audit_log WHERE action = 'TOKEN_EXCHANGE_DENIED' "
                + "AND after_state::text LIKE '%invocation_context_denied%' AND tenant_id = ?", Integer.class, w.tenant))
                .isGreaterThanOrEqualTo(6);
        assertThat(jdbc.queryForObject("SELECT count(*) FROM audit_log WHERE after_state::text LIKE ?", Integer.class,
                "%" + good + "%")).as("evidence never audited").isZero();
    }

    @Test
    void issuanceRetriesAreExactlyOnceAndConcurrentRunsAreIndependent() throws Exception {
        World w = world("icb-a");
        Entry e = enter(w, "claims", member(w, "claims"));
        String evidence = evidence(w, e, w.agentAud, Set.of(SCOPE), Instant.now().plusSeconds(600));
        List<Map<String, Object>> retries = parallel(8, i -> claims(token(exchange(w.broker, e.p3(), w.agentAud, SCOPE,
                Map.of("invocation_authorization", evidence, "invocation_idempotency_key", "issue-1")))));
        Set<Object> contexts = new HashSet<>();
        retries.forEach(c -> contexts.add(c.get("ctx")));
        assertThat(contexts).as("one context for all retries").hasSize(1);
        assertThat(jdbc.queryForObject("SELECT count(*) FROM invocation_contexts WHERE idempotency_key = 'issue-1' "
                + "AND tenant_id = ?", Integer.class, w.tenant)).isEqualTo(1);
        // the same key for a different request is refused
        Entry other = enter(w, "claims", member(w, "claims"));
        denied(exchange(w.broker, other.p3(), w.agentAud, SCOPE, Map.of("invocation_authorization",
                evidence(w, other, w.agentAud, Set.of(SCOPE), Instant.now().plusSeconds(600)),
                "invocation_idempotency_key", "issue-1")), "invalid_grant");

        // independent runs in one session (distinct evidence) are created concurrently and stay distinct
        Entry runs = enter(w, "wealth", member(w, "wealth"));
        List<Map<String, Object>> parallelRuns = parallel(4, i -> claims(token(exchange(w.broker, runs.p3(), w.agentAud,
                SCOPE, Map.of("invocation_authorization", evidence(w, runs, w.agentAud, Set.of(SCOPE),
                        Instant.now().plusSeconds(600)))))));
        Set<Object> runContexts = new HashSet<>();
        parallelRuns.forEach(c -> runContexts.add(c.get("ctx")));
        assertThat(runContexts).hasSize(4);
        assertThat(jdbc.queryForObject("SELECT count(DISTINCT root_session_id) FROM invocation_contexts WHERE "
                + "originating_subject = ?", Integer.class, runs.user())).isEqualTo(1);
    }

    @Test
    void activeContextsPerSessionAreBounded() throws Exception {
        World w = world("icb-a");
        Entry e = enter(w, "claims", member(w, "claims"));
        for (int i = 0; i < MAX_ACTIVE_PER_SESSION; i++) establish(w, e, Map.of());
        denied(exchange(w.broker, e.p3(), w.agentAud, SCOPE, Map.of("invocation_authorization",
                evidence(w, e, w.agentAud, Set.of(SCOPE), Instant.now().plusSeconds(600)))), InvocationContextService.LIMIT_EXCEEDED);
        // another session of another user is unaffected
        establish(w, enter(w, "claims", member(w, "claims")), Map.of());
    }

    @Test
    void contextStateSurvivesAnApplicationRestart() throws Exception {
        World w = world("icb-a");
        Entry e = enter(w, "claims", member(w, "claims"));
        Established est = establish(w, e, Map.of());
        try (ConfigurableApplicationContext restarted = new SpringApplicationBuilder(IamApplication.class,
                SyntheticInvocationAuthorizationVerifier.Config.class).web(WebApplicationType.SERVLET)
                .run(commandLine())) {
            MockMvc fresh = MockMvcBuilders.webAppContextSetup((WebApplicationContext) restarted).apply(springSecurity()).build();
            assertThat(restarted.getBean(InvocationContextService.class).describe(w.tenant,
                    java.util.UUID.fromString(est.contextId()))).containsEntry("status", "ACTIVE").containsEntry("version", 1L);
            MvcResult continued = fresh.perform(org.springframework.test.web.servlet.request.MockMvcRequestBuilders
                    .post("/oauth/token").contentType(org.springframework.http.MediaType.APPLICATION_FORM_URLENCODED)
                    .header("Authorization", basic(w.agent)).param("grant_type", EXCHANGE).param("subject_token", est.token())
                    .param("subject_token_type", ACCESS).param("audience", w.gatewayAud).param("scope", SCOPE)).andReturn();
            assertThat(continued.getResponse().getStatus()).as(continued.getResponse().getContentAsString()).isEqualTo(200);
            Map<String, Object> next = claims(json.readTree(continued.getResponse().getContentAsString()).get("access_token").asText());
            assertThat(next).containsEntry("ctx", est.contextId()).containsEntry("ctx_depth", 1);
        }
    }

    /** Command-line arguments outrank application.yml, exactly like the test's dynamic properties. */
    private static String[] commandLine() {
        List<String> args = new ArrayList<>(List.of("--server.port=0"));
        properties().forEach((k, v) -> args.add("--" + k + "=" + v));
        return args.toArray(String[]::new);
    }

    interface Task<T> { T run(int i) throws Exception; }

    static <T> List<T> parallel(int n, Task<T> task) throws Exception {
        ExecutorService pool = Executors.newFixedThreadPool(n);
        try {
            List<Callable<T>> calls = new ArrayList<>();
            for (int i = 0; i < n; i++) { int k = i; calls.add(() -> task.run(k)); }
            List<T> out = new ArrayList<>();
            for (Future<T> f : pool.invokeAll(calls)) out.add(f.get());
            return out;
        } finally {
            pool.shutdownNow();
        }
    }
}
