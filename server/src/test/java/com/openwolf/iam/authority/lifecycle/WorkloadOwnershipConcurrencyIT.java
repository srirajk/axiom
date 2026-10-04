package com.openwolf.iam.authority.lifecycle;

import com.openwolf.iam.IamApplication;
import com.openwolf.iam.authority.AuthorityITSupport;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.web.servlet.MvcResult;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;

/**
 * Phase 3.10 ownership lifecycle under concurrent use: while workers continuously use one owned workload (client
 * credentials, Phase 1 exchange, standing-token introspection, task resume), the owner is removed from the team, or the
 * team is deleted, or the owner is disabled. No request that starts after the change has committed succeeds; tokens
 * issued before it stop at introspection. Reassignment (plus reactivation after a departure) restores use. Throughout,
 * the team owns the workload but never appears as a token subject or actor.
 */
@SpringBootTest(classes = IamApplication.class, webEnvironment = SpringBootTest.WebEnvironment.MOCK)
@AutoConfigureMockMvc
class WorkloadOwnershipConcurrencyIT extends AuthorityITSupport {
    static final String STANDING = "urn:openwolf:params:oauth:grant-type:standing-grant";

    record Fixture(Tenant t, Svc agent, Svc broker, Svc ledger, String gatewayAud, String team, String owner,
                   String standingToken, String task, String ccToken) {}

    @Test
    void membershipRemovalDuringConcurrentUseStopsEveryLaterRequest() throws Exception {
        Fixture f = fixture();
        race(f, () -> body(send(delete("/teams/" + f.team() + "/members/" + f.owner()), f.t().admin, null), 204));
        assertThat(introspect(f.ledger(), f.standingToken()).path("active").asBoolean()).isFalse();
        body(send(post("/teams/" + f.team() + "/members"), f.t().admin, Map.of("userId", f.owner())), 201);
        assertThat(uses(f)).as("restored by restoring the membership").containsOnly(true);
    }

    @Test
    void teamDeletionDuringConcurrentUseStopsEveryLaterRequestUntilReassigned() throws Exception {
        Fixture f = fixture();
        race(f, () -> body(send(delete("/teams/" + f.team()), f.t().admin, null), 204));
        String successor = principal(f.t().id, f.t().s + "-successor", null);
        String team2 = body(send(post("/teams"), f.t().admin, Map.of("name", f.t().s + "-team2")), 201).path("id").asText();
        body(send(post("/teams/" + team2 + "/members"), f.t().admin, Map.of("userId", successor)), 201);
        body(send(post(base(f.t()) + "/ciam/agent-workloads/" + f.agent().workloadId() + "/ownership"), f.t().admin,
                Map.of("teamId", team2, "accountablePrincipalId", successor)), 200);
        assertThat(uses(f)).as("restored by reassignment").containsOnly(true);
    }

    @Test
    void ownerDepartureDuringConcurrentUseSuspendsDurably() throws Exception {
        Fixture f = fixture();
        race(f, () -> body(send(put("/users/" + f.owner()), f.t().admin, Map.of("isActive", false)), 200));
        assertThat(jdbc.queryForObject("SELECT status FROM agent_workload_identities WHERE id = ?::uuid", String.class,
                f.agent().workloadId())).isEqualTo("SUSPENDED");
        body(send(put("/users/" + f.owner()), f.t().admin, Map.of("isActive", true)), 200);
        assertThat(uses(f)).as("re-enabling the person does not reactivate the workload").containsOnly(false);
        body(send(post(base(f.t()) + "/ciam/agent-workloads/" + f.agent().workloadId() + "/reactivate"), f.t().admin,
                null), 200);
        // Client credentials, exchange and task use return; the standing token issued before the departure does not:
        // disabling the owner revoked every session of that person, including the one bound to that token.
        assertThat(uses(f)).containsExactly(true, true, false, true);
    }

    @Test
    void aTeamOwnsTheWorkloadButIsNeverATokenSubjectOrActor() throws Exception {
        Fixture f = fixture();
        List<String> tokens = List.of(f.ccToken(), f.standingToken(),
                token(exchange(f.agent(), f.ccToken(), f.gatewayAud(), READ, Map.of())));
        for (String t : tokens) {
            Map<String, Object> c = claims(t);
            assertThat(c.get("sub")).isIn(f.owner(), f.agent().clientId());
            assertThat(String.valueOf(c)).doesNotContain(f.team());
        }
        MvcResult asTeam = mvc.perform(post("/oauth/token").contentType(org.springframework.http.MediaType.APPLICATION_FORM_URLENCODED)
                .param("grant_type", "client_credentials").param("client_id", f.team()).param("client_secret", "x")
                .param("scope", READ)).andReturn();
        assertThat(asTeam.getResponse().getStatus()).as("a team has no credential").isEqualTo(401);
    }

    // =================================================================================================================

    /** Workers use the workload continuously; {@code change} runs mid-way. Nothing starting after it may succeed. */
    private void race(Fixture f, Change change) throws Exception {
        AtomicBoolean changed = new AtomicBoolean();
        AtomicBoolean stop = new AtomicBoolean();
        List<String> lateSuccesses = Collections.synchronizedList(new ArrayList<>());
        List<Integer> earlySuccesses = Collections.synchronizedList(new ArrayList<>());
        ExecutorService pool = Executors.newFixedThreadPool(4);
        try {
            List<Future<?>> workers = new ArrayList<>();
            for (int i = 0; i < 4; i++) {
                int kind = i;
                workers.add(pool.submit(() -> {
                    while (!stop.get()) {
                        boolean after = changed.get();
                        boolean ok = use(f, kind);
                        if (ok && after) lateSuccesses.add("worker " + kind);
                        if (ok && !after) earlySuccesses.add(kind);
                    }
                    return null;
                }));
            }
            Thread.sleep(1500);
            change.run();
            changed.set(true);
            Thread.sleep(1500);
            stop.set(true);
            for (Future<?> w : workers) w.get(60, TimeUnit.SECONDS);
        } finally {
            pool.shutdownNow();
        }
        assertThat(earlySuccesses).as("the workload was in use before the change").isNotEmpty();
        assertThat(lateSuccesses).as("requests started after the change committed").isEmpty();
        assertThat(uses(f)).containsOnly(false);
    }

    interface Change { void run() throws Exception; }

    private List<Boolean> uses(Fixture f) throws Exception {
        List<Boolean> r = new ArrayList<>();
        for (int k = 0; k < 4; k++) r.add(use(f, k));
        return r;
    }

    private boolean use(Fixture f, int kind) throws Exception {
        return switch (kind) {
            case 0 -> tokenRequest(f.agent(), Map.of("grant_type", "client_credentials", "scope", READ))
                    .getResponse().getStatus() == 200;
            case 1 -> exchange(f.agent(), f.ccToken(), f.gatewayAud(), READ, Map.of()).getResponse().getStatus() == 200;
            case 2 -> introspect(f.ledger(), f.standingToken()).path("active").asBoolean();
            default -> send(post("/api/v1/workload/tasks/" + f.task() + "/resume"), f.ccToken(), null)
                    .getResponse().getStatus() == 200;
        };
    }

    private Fixture fixture() throws Exception {
        Tenant t = tenant("p3g-b");
        Svc agent = workload(t, "agent", List.of(READ));
        String gatewayAud = "gw:" + t.id + ":" + t.s;
        Svc broker = confidential(t, app(t, "gw", gatewayAud), gatewayAud, t.s + "-broker", List.of(READ));
        body(send(post(base(t) + "/agent-exchange/brokers"), t.admin, Map.of("oauthClientId", broker.clientId(),
                "gatewayAudience", gatewayAud, "scopes", List.of(READ))), 201);
        route(t, agent.workloadId(), "GATEWAY", null, gatewayAud, List.of(READ));
        String ledgerAud = "ledger:" + t.id + ":" + t.s;
        Svc ledger = confidential(t, app(t, "ledger", ledgerAud), ledgerAud, t.s + "-ledger", List.of(READ));
        route(t, agent.workloadId(), "RESOURCE", null, ledgerAud, List.of(READ));
        String owner = principal(t.id, t.s + "-owner", null);
        entitle(t, agent.appId(), owner, List.of(READ));
        String team = body(send(post("/teams"), t.admin, Map.of("name", t.s + "-team")), 201).path("id").asText();
        body(send(post("/teams/" + team + "/members"), t.admin, Map.of("userId", owner)), 201);
        body(send(post(base(t) + "/ciam/agent-workloads/" + agent.workloadId() + "/ownership"), t.admin,
                Map.of("teamId", team, "accountablePrincipalId", owner)), 200);
        String grant = body(send(post("/api/me/standing-grants"), login(owner), Map.of("agentWorkloadId",
                agent.workloadId(), "audience", ledgerAud, "scopes", List.of(READ), "purpose", "Nightly",
                "expiresAt", Instant.now().plusSeconds(1800).toString())), 201).path("id").asText();
        String standing = tokenResponse(tokenRequest(agent, Map.of("grant_type", STANDING, "standing_grant", grant,
                "scope", READ))).path("access_token").asText();
        String cc = clientCredentials(agent, READ);
        String task = body(send(post("/api/v1/workload/tasks"), cc, Map.of("authorityType", "STANDING_GRANT",
                "authorityId", grant, "taskRef", "race")), 201).path("id").asText();
        Fixture f = new Fixture(t, agent, broker, ledger, gatewayAud, team, owner, standing, task, cc);
        assertThat(uses(f)).as("baseline").containsOnly(true);
        return f;
    }
}
