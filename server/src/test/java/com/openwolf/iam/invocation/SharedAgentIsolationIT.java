package com.openwolf.iam.invocation;

import com.openwolf.iam.IamApplication;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.test.web.servlet.MvcResult;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Gate E — Phase 2.12 security audit and the Axiom/fixture side of 2.13: two users in two Use Cases (Claims, Wealth)
 * run concurrently through ONE Agent identity. This proves Axiom's token and context authority only; it says nothing
 * about real Agent memory, budgets, data isolation or Gateway/Cerbos enforcement.
 */
@SpringBootTest(classes = IamApplication.class, webEnvironment = SpringBootTest.WebEnvironment.MOCK)
@AutoConfigureMockMvc
@Import(SyntheticInvocationAuthorizationVerifier.Config.class)
class SharedAgentIsolationIT extends InvocationContextITSupport {

    @Test
    void twoUsersTwoUseCasesOneAgentStayIsolatedAndRevocationIsScoped() throws Exception {
        World w = world("ice-a");
        Entry claims = enter(w, "claims", member(w, "claims"));
        Entry wealth = enter(w, "wealth", member(w, "wealth"));
        Established claimsRun = establish(w, claims, Map.of("invocation_run", "claims-run"));
        Established wealthRun = establish(w, wealth, Map.of("invocation_run", "wealth-run"));
        List<String> issued = Collections.synchronizedList(new ArrayList<>(List.of(claimsRun.token(), wealthRun.token())));

        // Concurrent work through the same Agent identity; Wealth is revoked part-way.
        ExecutorService pool = Executors.newFixedThreadPool(2);
        CountDownLatch halfway = new CountDownLatch(1);
        try {
            Future<List<Integer>> claimsWork = pool.submit(() -> run(w, claimsRun, issued, 12, null));
            Future<List<Integer>> wealthWork = pool.submit(() -> run(w, wealthRun, issued, 12, halfway));
            halfway.await(60, TimeUnit.SECONDS);
            body(revokeContext(w, wealthRun.contextId()), 200);
            List<Integer> claimsStatuses = claimsWork.get(120, TimeUnit.SECONDS);
            List<Integer> wealthStatuses = wealthWork.get(120, TimeUnit.SECONDS);
            assertThat(claimsStatuses).as("Claims continues throughout").containsOnly(200);
            assertThat(wealthStatuses).as("Wealth worked, then stopped").contains(200);
            assertThat(wealthStatuses.get(wealthStatuses.size() - 1)).isNotEqualTo(200);
        } finally {
            pool.shutdownNow();
        }
        denied(exchange(w.agent, wealthRun.token(), w.gatewayAud, SCOPE, Map.of()), "invalid_grant");
        Map<String, Object> claimsNext = claims(token(exchange(w.agent, claimsRun.token(), w.gatewayAud, SCOPE, Map.of())));
        assertThat(claimsNext).containsEntry("ctx", claimsRun.contextId()).containsEntry("sub", claims.user());

        // Authority substitution attempts by the shared Agent / broker.
        denied(exchange(w.broker, claims.p3(), w.agentAud, SCOPE, Map.of("invocation_context", wealthRun.contextId())),
                "invalid_grant");
        denied(exchange(w.broker, wealth.p3(), w.agentAud, SCOPE, Map.of("invocation_context", claimsRun.contextId())),
                "invalid_grant");
        denied(exchange(w.broker, claims.p3(), w.agentAud, SCOPE, Map.of("invocation_authorization",
                evidence(w, wealth, w.agentAud, Set.of(SCOPE), Instant.now().plusSeconds(600)))), "invalid_grant");
        assertThat(introspect(w.agent, claimsRun.token()).path("invocation_context").path("use_case_application_id").asText())
                .isEqualTo(claims.useCase().appId);

        // Security audit reconstructs issuance, continuation, revocation and denial without traces.
        for (Established run : List.of(claimsRun, wealthRun)) {
            assertThat(count("INVOCATION_CONTEXT_ESTABLISHED", run.contextId())).isEqualTo(1);
            List<Map<String, Object>> exchanges = jdbc.queryForList("SELECT after_state::text AS a FROM audit_log WHERE "
                    + "action = 'TOKEN_EXCHANGE_SUCCEEDED' AND after_state->>'context_id' = ?", run.contextId());
            assertThat(exchanges).isNotEmpty();
            for (Map<String, Object> entry : exchanges) {
                String a = (String) entry.get("a");
                assertThat(a).contains("\"token_id\"").contains("\"subject\": \"" + run.entry().user() + "\"")
                        .contains("\"context_version\": 1").contains("\"actor\"").contains("\"decision\"");
            }
        }
        assertThat(count("INVOCATION_CONTEXT_REVOKED", wealthRun.contextId())).isEqualTo(1);
        assertThat(jdbc.queryForObject("SELECT count(*) FROM audit_log WHERE action = 'TOKEN_EXCHANGE_DENIED' AND "
                + "after_state->>'context_reason' IN ('context revoked', 'stale context version') AND tenant_id = ?",
                Integer.class, w.tenant)).isGreaterThan(0);
        // No bearer token (or its signature) and no authorization evidence is ever stored in audit.
        String auditText = String.join("\n", jdbc.queryForList(
                "SELECT coalesce(before_state::text,'') || coalesce(after_state::text,'') FROM audit_log WHERE tenant_id = ?",
                String.class, w.tenant));
        for (String t : issued) {
            assertThat(auditText).doesNotContain(t.substring(t.lastIndexOf('.') + 1));
        }
        assertThat(auditText).doesNotContain("invocation_authorization");
    }

    /** Agent continuation then broker resource exchange, repeatedly; returns the final status of each iteration. */
    private List<Integer> run(World w, Established est, List<String> issued, int iterations, CountDownLatch halfway)
            throws Exception {
        List<Integer> statuses = new ArrayList<>();
        for (int i = 0; i < iterations; i++) {
            MvcResult toGateway = exchange(w.agent, est.token(), w.gatewayAud, SCOPE, Map.of());
            int status = toGateway.getResponse().getStatus();
            if (status == 200) {
                String p5 = token(toGateway);
                issued.add(p5);
                MvcResult toTool = exchange(w.broker, p5, w.toolAud, SCOPE, Map.of());
                status = toTool.getResponse().getStatus();
                if (status == 200) {
                    String p6 = token(toTool);
                    issued.add(p6);
                    Map<String, Object> c = claims(p6);
                    assertThat(c).containsEntry("ctx", est.contextId()).containsEntry("sub", est.entry().user());
                }
            }
            statuses.add(status);
            if (halfway != null && i == iterations / 2) halfway.countDown();
            if (halfway != null && i > iterations / 2) Thread.sleep(50);
        }
        if (halfway != null) halfway.countDown();
        return statuses;
    }

    private int count(String action, String contextId) {
        return jdbc.queryForObject("SELECT count(*) FROM audit_log WHERE action = ? AND resource_id = ?", Integer.class,
                action, contextId);
    }
}
