package com.openwolf.iam.invocation;

import com.fasterxml.jackson.databind.JsonNode;
import com.openwolf.iam.IamApplication;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.test.web.servlet.MvcResult;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

/** Gate C — Phase 2.4 context-bound tokens, 2.5 continuation limits and 2.6 fail-closed resolution. */
@SpringBootTest(classes = IamApplication.class, webEnvironment = SpringBootTest.WebEnvironment.MOCK)
@AutoConfigureMockMvc
@Import(SyntheticInvocationAuthorizationVerifier.Config.class)
class InvocationContextContinuationIT extends InvocationContextITSupport {

    @Test
    void everyHopCarriesTheBoundContextAndOnlyAttenuates() throws Exception {
        World w = world("icc-a");
        Established est = establish(w, enter(w, "claims", member(w, "claims")), Map.of());
        String p5 = token(exchange(w.agent, est.token(), w.gatewayAud, SCOPE, Map.of()));
        String p6 = token(exchange(w.broker, p5, w.toolAud, SCOPE, Map.of()));
        long deadline = ((java.sql.Timestamp) row(est.contextId()).get("deadline")).toInstant().getEpochSecond();
        Set<Object> tokenIds = new HashSet<>();
        int depth = 0;
        for (String t : List.of(est.token(), p5, p6)) {
            Map<String, Object> c = claims(t);
            assertThat(c).containsEntry("ctx", est.contextId()).containsEntry("ctx_ver", 1).containsEntry("ctx_depth", depth++)
                    .containsEntry("sub", est.entry().user()).containsKey("jti");
            assertThat(scopes(c)).containsExactly(SCOPE);
            assertThat(number(c, "exp")).isLessThanOrEqualTo(deadline);
            assertThat(tokenIds.add(c.get("jti"))).isTrue();
        }
        assertThat(act(claims(est.token()))).containsEntry("client_id", est.entry().useCase().entry.clientId());
        assertThat(act(claims(p5))).containsEntry("client_id", w.agent.clientId());
        assertThat(act(claims(p6))).containsEntry("client_id", w.agent.clientId());
        assertThat(claims(p6)).containsEntry("client_id", w.broker.clientId()).containsEntry("token_use", "delegated_access");
    }

    @Test
    void contextIdPossessionGrantsNothingAndFactsGoOnlyToTheRecipient() throws Exception {
        World w = world("icc-a");
        Entry owner = enter(w, "claims", member(w, "claims"));
        Established est = establish(w, owner, Map.of());
        JsonNode recipient = introspect(w.agent, est.token());
        assertThat(recipient.path("active").asBoolean()).isTrue();
        assertThat(recipient.path("invocation_context").path("id").asText()).isEqualTo(est.contextId());
        assertThat(recipient.path("invocation_context").path("use_case_application_id").asText()).isEqualTo(owner.useCase().appId);
        assertThat(introspect(w.sibling, est.token()).path("active").asBoolean()).as("non-recipient").isFalse();
        assertThat(introspect(w.broker, est.token()).path("active").asBoolean()).as("broker is not the recipient").isFalse();

        // Another user's Gateway authorization cannot attach to this context by naming its id.
        Entry stranger = enter(w, "claims", member(w, "claims"));
        denied(exchange(w.broker, stranger.p3(), w.agentAud, SCOPE, Map.of("invocation_context", est.contextId())),
                "invalid_grant");
        // A fresh Gateway authorization from the SAME login (same root session) resumes the context.
        UseCase uc = owner.useCase();
        String freshP2 = token(exchange(uc.entry, owner.p1(), uc.aud, SCOPE, Map.of()));
        String freshP3 = token(exchange(uc.entry, freshP2, w.gatewayAud, SCOPE, Map.of()));
        Map<String, Object> resumed = claims(token(exchange(w.broker, freshP3, w.agentAud, SCOPE,
                Map.of("invocation_context", est.contextId()))));
        assertThat(resumed).containsEntry("ctx", est.contextId()).containsEntry("ctx_depth", 0)
                .containsEntry("sub", owner.user());
        // The same user's NEW login is a different root session and cannot resume it.
        Entry newLogin = enter(w, "claims", owner.user());
        assertThat(newLogin.rootSession()).isNotEqualTo(owner.rootSession());
        denied(exchange(w.broker, newLogin.p3(), w.agentAud, SCOPE, Map.of("invocation_context", est.contextId())),
                "invalid_grant");
    }

    @Test
    void aSharedAgentCannotSubstituteAnotherUserUseCaseOrTenant() throws Exception {
        World a = world("icc-a");
        World b = world("icc-b");
        Entry claims = enter(a, "claims", member(a, "claims"));
        Entry wealth = enter(a, "wealth", member(a, "wealth"));
        Established c1 = establish(a, claims, Map.of());
        Established c2 = establish(a, wealth, Map.of());
        // One Agent identity continues both runs; each continuation keeps its own subject and context.
        Map<String, Object> n1 = claims(token(exchange(a.agent, c1.token(), a.gatewayAud, SCOPE, Map.of())));
        Map<String, Object> n2 = claims(token(exchange(a.agent, c2.token(), a.gatewayAud, SCOPE, Map.of())));
        assertThat(n1).containsEntry("ctx", c1.contextId()).containsEntry("sub", claims.user());
        assertThat(n2).containsEntry("ctx", c2.contextId()).containsEntry("sub", wealth.user());
        assertThat(introspect(a.agent, c2.token()).path("invocation_context").path("use_case_application_id").asText())
                .isEqualTo(wealth.useCase().appId);
        // Wealth's authorization cannot establish authority over Claims' Gateway token (and vice versa).
        denied(exchange(a.broker, claims.p3(), a.agentAud, SCOPE, Map.of("invocation_authorization",
                evidence(a, wealth, a.agentAud, Set.of(SCOPE), Instant.now().plusSeconds(600)))), "invalid_grant");
        // Claims' context cannot be resumed with Wealth's Gateway token.
        denied(exchange(a.broker, wealth.p3(), a.agentAud, SCOPE, Map.of("invocation_context", c1.contextId())), "invalid_grant");
        // Tenant B's Agent and broker cannot use tenant A's context.
        denied(exchange(b.agent, c1.token(), b.gatewayAud, SCOPE, Map.of()), "unauthorized_client");
        Entry bEntry = enter(b, "claims", member(b, "claims"));
        denied(exchange(b.broker, bEntry.p3(), b.agentAud, SCOPE, Map.of("invocation_context", c1.contextId())), "invalid_grant");
    }

    @Test
    void wrongActorOrAudienceIsRefused() throws Exception {
        World w = world("icc-a");
        Established est = establish(w, enter(w, "claims", member(w, "claims")), Map.of());
        denied(exchange(w.sibling, est.token(), w.gatewayAud, SCOPE, Map.of()), "invalid_grant");
        denied(exchange(w.broker, est.token(), w.toolAud, SCOPE, Map.of()), "invalid_grant");
        denied(exchange(w.agent, est.token(), w.toolAud, SCOPE, Map.of()), "invalid_target");
        String p5 = token(exchange(w.agent, est.token(), w.gatewayAud, SCOPE, Map.of()));
        denied(exchange(w.agent, p5, w.toolAud, SCOPE, Map.of()), "invalid_grant");
    }

    @Test
    void revokedOrStaleContextFailsClosedEverywhere() throws Exception {
        World w = world("icc-a");
        Entry e = enter(w, "claims", member(w, "claims"));
        Established est = establish(w, e, Map.of("invocation_idempotency_key", "run-x"));
        String p5 = token(exchange(w.agent, est.token(), w.gatewayAud, SCOPE, Map.of()));
        body(revokeContext(w, est.contextId()), 200);
        assertThat(row(est.contextId())).containsEntry("status", "REVOKED").containsEntry("version", 2L);
        denied(exchange(w.agent, est.token(), w.gatewayAud, SCOPE, Map.of()), "invalid_grant");
        denied(exchange(w.broker, p5, w.toolAud, SCOPE, Map.of()), "invalid_grant");
        assertThat(introspect(w.agent, est.token()).path("active").asBoolean()).isFalse();
        denied(exchange(w.broker, e.p3(), w.agentAud, SCOPE, Map.of("invocation_context", est.contextId())), "invalid_grant");
        denied(exchange(w.broker, e.p3(), w.agentAud, SCOPE, Map.of("invocation_authorization",
                evidence(w, e, w.agentAud, Set.of(SCOPE), Instant.now().plusSeconds(600)), "invocation_idempotency_key", "run-x")),
                "invalid_grant");
        // A second revoke does not move the version: a revoked context never changes again.
        body(revokeContext(w, est.contextId()), 200);
        assertThat(row(est.contextId())).containsEntry("version", 2L);
    }

    @Test
    void widenedResumeExcessiveDepthAndExpiredDeadlineAreRefused() throws Exception {
        World w = world("icc-a");
        String user = member(w, "claims");
        Entry e = enter(w, "claims", user);
        Established est = establish(w, e, Map.of());
        // Resume with a Gateway token carrying more scope than the context ceiling.
        UseCase uc = w.uc("claims");
        String p2wide = token(exchange(uc.entry, e.p1(), uc.aud, SCOPE + " " + EXTRA, Map.of()));
        String p3wide = token(exchange(uc.entry, p2wide, w.gatewayAud, SCOPE + " " + EXTRA, Map.of()));
        denied(exchange(w.broker, p3wide, w.agentAud, SCOPE + " " + EXTRA, Map.of("invocation_context", est.contextId())),
                "invalid_grant");
        // Depth: establishment 0, Agent->Gateway 1, broker->Agent2 2, Agent2->Gateway would be 3 > MAX_DEPTH.
        String p5 = token(exchange(w.agent, est.token(), w.gatewayAud, SCOPE, Map.of()));
        String toAgent2 = token(exchange(w.broker, p5, w.agent2Aud, SCOPE, Map.of()));
        assertThat(claims(toAgent2)).containsEntry("ctx_depth", MAX_DEPTH);
        denied(exchange(w.agent2, toAgent2, w.gatewayAud, SCOPE, Map.of()), "invalid_grant");
        // Deadline: a 3-second context cannot be continued after it ends, and no token outlives it.
        Established shortLived = establish(w, e, Map.of("invocation_ttl", "3"));
        long deadline = ((java.sql.Timestamp) row(shortLived.contextId()).get("deadline")).toInstant().getEpochSecond();
        assertThat(number(claims(shortLived.token()), "exp")).isLessThanOrEqualTo(deadline);
        Thread.sleep(Math.max(0, deadline * 1000 - System.currentTimeMillis()) + 1500);
        denied(exchange(w.agent, shortLived.token(), w.gatewayAud, SCOPE, Map.of()), "invalid_grant");
    }

    @Test
    void repeatedExchangeIsAllowedUntilRevocation() throws Exception {
        World w = world("icc-a");
        Established est = establish(w, enter(w, "claims", member(w, "claims")), Map.of());
        String first = token(exchange(w.agent, est.token(), w.gatewayAud, SCOPE, Map.of()));
        String retry = token(exchange(w.agent, est.token(), w.gatewayAud, SCOPE, Map.of()));
        assertThat(claims(first).get("jti")).isNotEqualTo(claims(retry).get("jti"));
        assertThat(claims(retry)).containsEntry("ctx", est.contextId());
        body(revokeContext(w, est.contextId()), 200);
        for (String t : List.of(est.token(), first, retry)) {
            assertThat(introspect(t.equals(est.token()) ? w.agent : w.broker, t).path("active").asBoolean()).isFalse();
        }
        denied(exchange(w.agent, est.token(), w.gatewayAud, SCOPE, Map.of()), "invalid_grant");
    }

    @Test
    void concurrentBranchesAreIndependentAndBounded() throws Exception {
        World w = world("icc-a");
        Established est = establish(w, enter(w, "claims", member(w, "claims")), Map.of());
        List<MvcResult> results = InvocationContextEstablishmentIT.parallel(MAX_BRANCHES + 4, i ->
                exchange(w.agent, est.token(), w.gatewayAud, SCOPE, Map.of("invocation_branch", "b" + i)));
        List<String> branches = new java.util.ArrayList<>();
        int limited = 0;
        for (MvcResult r : results) {
            if (r.getResponse().getStatus() == 200) branches.add(token(r));
            else { denied(r, InvocationContextService.LIMIT_EXCEEDED); limited++; }
        }
        assertThat(branches).hasSize(MAX_BRANCHES);
        assertThat(limited).isEqualTo(4);
        Set<Object> ids = new HashSet<>();
        for (String b : branches) {
            Map<String, Object> c = claims(b);
            assertThat(c.get("ctx")).isNotEqualTo(est.contextId());
            ids.add(c.get("ctx"));
        }
        assertThat(ids).hasSize(MAX_BRANCHES);
        String b0 = branches.get(0);
        String b1 = branches.get(1);
        // revoke one branch: it stops; its sibling and the root continue
        body(revokeContext(w, (String) claims(b0).get("ctx")), 200);
        denied(exchange(w.broker, b0, w.toolAud, SCOPE, Map.of()), "invalid_grant");
        token(exchange(w.broker, b1, w.toolAud, SCOPE, Map.of()));
        token(exchange(w.agent, est.token(), w.gatewayAud, SCOPE, Map.of()));
        // revoke the root: every branch stops
        body(revokeContext(w, est.contextId()), 200);
        denied(exchange(w.broker, b1, w.toolAud, SCOPE, Map.of()), "invalid_grant");
    }

    @Test
    void tokenAndHeaderSizesAreMeasured() throws Exception {
        World w = world("icc-a");
        Entry e = enter(w, "claims", member(w, "claims"));
        Established est = establish(w, e, Map.of("invocation_run", "run-size-1"));
        String plainP4 = token(exchange(w.broker, e.p3(), w.agentAud, SCOPE, Map.of()));
        String p5 = token(exchange(w.agent, est.token(), w.gatewayAud, SCOPE, Map.of()));
        String p6 = token(exchange(w.broker, p5, w.toolAud, SCOPE, Map.of()));
        String cookies = "SESSION=" + "s".repeat(48) + "; XSRF-TOKEN=" + "x".repeat(36) + "; _ga=GA1.1." + "1".repeat(20);
        String traceparent = "00-" + "a".repeat(32) + "-" + "b".repeat(16) + "-01";
        String forwarding = "for=10.1.2.3;proto=https;host=gateway.example.internal";
        Map<String, Object> sizes = new LinkedHashMap<>();
        sizes.put("human_session_token_bytes", e.p1().length());
        sizes.put("gateway_authorization_token_bytes", e.p3().length());
        sizes.put("agent_token_without_context_bytes", plainP4.length());
        sizes.put("agent_token_with_context_bytes", est.token().length());
        sizes.put("context_overhead_bytes", est.token().length() - plainP4.length());
        sizes.put("continuation_token_bytes", p5.length());
        sizes.put("resource_token_bytes", p6.length());
        int headers = ("Authorization: Bearer " + est.token()).length() + ("Cookie: " + cookies).length()
                + ("traceparent: " + traceparent).length() + ("tracestate: vendor=" + "t".repeat(40)).length()
                + ("Forwarded: " + forwarding).length() + ("X-Forwarded-For: 10.1.2.3, 10.4.5.6").length();
        sizes.put("representative_request_headers_bytes", headers);
        Path out = Path.of("target", "phase2-token-sizes.json");
        Files.writeString(out, json.writerWithDefaultPrettyPrinter().writeValueAsString(sizes), StandardCharsets.UTF_8);
        System.out.println("PHASE2_TOKEN_SIZES " + json.writeValueAsString(sizes));
        assertThat(est.token().length()).isGreaterThan(plainP4.length());
    }
}
