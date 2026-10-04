package com.openwolf.iam.authority.lifecycle;

import com.fasterxml.jackson.databind.JsonNode;
import com.openwolf.iam.IamApplication;
import com.openwolf.iam.authority.AuthorityITSupport;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.web.servlet.MvcResult;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;

/**
 * Phase 3.15 trace of every authority path an Agent workload has: client-credentials issuance and introspection of its
 * own token, the workload API, Phase 1 token exchange (and the exchanged token), standing-grant renewal and token,
 * approved-action redemption and token, durable tasks. After suspension each path refuses — for tokens issued before
 * and for new requests — while another workload and an ordinary (non-Agent) service client are unaffected; reactivation
 * restores the paths; retirement is terminal (no reactivation, no re-registration of the client, no ownership change).
 */
@SpringBootTest(classes = IamApplication.class, webEnvironment = SpringBootTest.WebEnvironment.MOCK)
@AutoConfigureMockMvc
class WorkloadSuspensionPathsIT extends AuthorityITSupport {
    static final String STANDING = "urn:openwolf:params:oauth:grant-type:standing-grant";
    static final String APPROVED = "urn:openwolf:params:oauth:grant-type:approved-action";

    /** One Agent with every kind of authority, plus an independent set for comparison. */
    final class Agent {
        Svc svc;
        String grant, handle, task;
        final Map<String, String> tokens = new LinkedHashMap<>();
    }

    record World(Tenant t, Svc broker, Svc receiver, Svc plainService, String gatewayAud, String ledgerAud,
                 String owner, String approver) {}

    @Test
    void suspensionStopsEveryPathOfThatWorkloadOnlyAndReactivationRestoresThem() throws Exception {
        World w = world();
        Agent a = agent(w, "a");
        Agent b = agent(w, "b");

        suspend(w, a);
        assertThat(existing(w, a)).as("tokens issued before suspension").allSatisfy((k, v) -> assertThat(v).as(k).isFalse());
        assertThat(fresh(w, a)).as("new requests after suspension").allSatisfy((k, v) -> assertThat(v).as(k).isFalse());
        assertThat(existing(w, b)).as("another workload").allSatisfy((k, v) -> assertThat(v).as(k).isTrue());
        assertThat(fresh(w, b)).as("another workload").allSatisfy((k, v) -> assertThat(v).as(k).isTrue());
        assertThat(tokenRequest(w.plainService(), Map.of("grant_type", "client_credentials", "scope", READ))
                .getResponse().getStatus()).as("ordinary (non-Agent) service client").isEqualTo(200);

        body(send(post(lifecycle(w, a) + "/reactivate"), w.t().admin, null), 200);
        assertThat(fresh(w, a)).as("after reactivation").allSatisfy((k, v) -> assertThat(v).as(k).isTrue());
    }

    @Test
    void retirementIsTerminalForEveryPath() throws Exception {
        World w = world();
        Agent a = agent(w, "a");
        body(send(post(lifecycle(w, a) + "/retire"), w.t().admin, Map.of("reason", "decommissioned")), 200);
        assertThat(existing(w, a)).allSatisfy((k, v) -> assertThat(v).as(k).isFalse());
        assertThat(fresh(w, a)).allSatisfy((k, v) -> assertThat(v).as(k).isFalse());
        assertThat(send(post(lifecycle(w, a) + "/reactivate"), w.t().admin, null).getResponse().getStatus()).isEqualTo(409);
        assertThat(send(post(lifecycle(w, a) + "/suspend"), w.t().admin, null).getResponse().getStatus()).isEqualTo(409);
        assertThat(send(post(base(w.t()) + "/ciam/agent-workloads"), w.t().admin, Map.of("workloadRef",
                "agent:reuse:" + UUID.randomUUID(), "name", "reuse", "oauthClientId", a.svc.clientId()))
                .getResponse().getStatus()).as("the retired client cannot be registered again").isIn(400, 409);
        assertThat(jdbc.queryForObject("SELECT status FROM agent_workload_identities WHERE id = ?::uuid", String.class,
                a.svc.workloadId())).isEqualTo("RETIRED");
        assertThat(jdbc.queryForObject("SELECT status FROM tenant_application_clients WHERE client_id = ?",
                String.class, a.svc.clientId())).as("the OAuth client row is not disabled").isEqualTo("ACTIVE");
    }

    // =================================================================================================================

    /** Introspection (by the right recipient) of every token the Agent held before the change. */
    private Map<String, Boolean> existing(World w, Agent a) throws Exception {
        Map<String, Boolean> r = new LinkedHashMap<>();
        // Client-credentials tokens carry no Axiom session, so introspection never reports them active (existing
        // behaviour for every client); their uses are the workload API and the subject of a token exchange.
        r.put("exchange with existing client-credentials token",
                exchange(a.svc, a.tokens.get("cc"), w.gatewayAud(), READ, Map.of()).getResponse().getStatus() == 200);
        r.put("exchanged Gateway token", introspect(w.broker(), a.tokens.get("gateway")).path("active").asBoolean());
        r.put("standing-grant token", introspect(w.receiver(), a.tokens.get("standing")).path("active").asBoolean());
        r.put("approved-action token", introspect(w.receiver(), a.tokens.get("approved")).path("active").asBoolean());
        r.put("workload API with existing token",
                send(post("/api/v1/workload/tasks/" + a.task + "/resume"), a.tokens.get("cc"), null).getResponse().getStatus() == 200);
        return r;
    }

    /** Every way to obtain new authority. */
    private Map<String, Boolean> fresh(World w, Agent a) throws Exception {
        Map<String, Boolean> r = new LinkedHashMap<>();
        MvcResult cc = tokenRequest(a.svc, Map.of("grant_type", "client_credentials", "scope", READ));
        r.put("client-credentials issuance", cc.getResponse().getStatus() == 200);
        String bearer = cc.getResponse().getStatus() == 200 ? token(cc) : a.tokens.get("cc");
        r.put("token exchange", exchange(a.svc, bearer, w.gatewayAud(), READ, Map.of()).getResponse().getStatus() == 200);
        MvcResult renewed = tokenRequest(a.svc, Map.of("grant_type", STANDING, "standing_grant", a.grant,
                "renewal_handle", a.handle, "scope", READ));
        if (renewed.getResponse().getStatus() == 200) a.handle = tokenResponse(renewed).path("renewal_handle").asText();
        r.put("standing renewal", renewed.getResponse().getStatus() == 200);
        r.put("approved-action redemption", approvedToken(w, a) != null);
        r.put("task creation", send(post("/api/v1/workload/tasks"), bearer, Map.of("authorityType", "STANDING_GRANT",
                "authorityId", a.grant, "taskRef", "t-" + UUID.randomUUID().toString().substring(0, 8)))
                .getResponse().getStatus() == 201);
        return r;
    }

    private World world() throws Exception {
        Tenant t = tenant("p3g-a");
        String gatewayAud = "gw:" + t.id + ":" + t.s;
        Svc broker = confidential(t, app(t, "gw", gatewayAud), gatewayAud, t.s + "-broker", List.of(READ, PAY));
        body(send(post(base(t) + "/agent-exchange/brokers"), t.admin, Map.of("oauthClientId", broker.clientId(),
                "gatewayAudience", gatewayAud, "scopes", List.of(READ, PAY))), 201);
        String ledgerAud = "ledger:" + t.id + ":" + t.s;
        String ledgerApp = app(t, "ledger", ledgerAud);
        Svc receiver = confidential(t, ledgerApp, ledgerAud, t.s + "-ledger", List.of(READ));
        String plainAud = "svc:" + t.id + ":" + t.s;
        Svc plain = confidential(t, app(t, "plain", plainAud), plainAud, t.s + "-plain", List.of(READ));
        String owner = principal(t.id, t.s + "-owner", null);
        String approver = principal(t.id, t.s + "-approver", "action_approver");
        return new World(t, broker, receiver, plain, gatewayAud, ledgerAud, owner, approver);
    }

    private Agent agent(World w, String name) throws Exception {
        Tenant t = w.t();
        Agent a = new Agent();
        a.svc = workload(t, name, List.of(READ, PAY));
        route(t, a.svc.workloadId(), "GATEWAY", null, w.gatewayAud(), List.of(READ));
        route(t, a.svc.workloadId(), "RESOURCE", null, w.ledgerAud(), List.of(READ, PAY));
        entitle(t, a.svc.appId(), w.owner(), Map.of(READ, "allow", PAY, "cosign"));
        a.grant = body(send(post("/api/me/standing-grants"), login(w.owner()), Map.of("agentWorkloadId",
                a.svc.workloadId(), "audience", w.ledgerAud(), "scopes", List.of(READ), "purpose", "Nightly",
                "expiresAt", Instant.now().plusSeconds(1800).toString())), 201).path("id").asText();
        JsonNode standing = tokenResponse(tokenRequest(a.svc, Map.of("grant_type", STANDING, "standing_grant", a.grant,
                "scope", READ)));
        a.handle = standing.path("renewal_handle").asText();
        a.tokens.put("standing", standing.path("access_token").asText());
        a.tokens.put("cc", clientCredentials(a.svc, READ));
        a.tokens.put("gateway", token(exchange(a.svc, a.tokens.get("cc"), w.gatewayAud(), READ, Map.of())));
        a.tokens.put("approved", approvedToken(w, a));
        a.task = body(send(post("/api/v1/workload/tasks"), a.tokens.get("cc"), Map.of("authorityType", "STANDING_GRANT",
                "authorityId", a.grant, "taskRef", "base")), 201).path("id").asText();
        assertThat(existing(w, a)).as("baseline").allSatisfy((k, v) -> assertThat(v).as(k).isTrue());
        return a;
    }

    /** Request → approval → confirmation (by people) → redemption by the Agent; null when any step is refused. */
    private String approvedToken(World w, Agent a) throws Exception {
        MvcResult requested = send(post("/api/v1/action-approvals"), login(w.owner()), Map.of("agentWorkloadId",
                a.svc.workloadId(), "receiverAudience", w.ledgerAud(), "scopes", List.of(PAY), "actionType",
                "payment.execute", "action", json.readTree("{\"invoice\":\"" + UUID.randomUUID() + "\"}"),
                "deadlineSeconds", 900, "maxAuthAgeSeconds", 60));
        if (requested.getResponse().getStatus() != 201) return null;
        JsonNode approval = json.readTree(requested.getResponse().getContentAsString());
        String id = approval.path("id").asText();
        String digest = approval.path("actionDigest").asText();
        body(send(post("/api/v1/action-approvals/" + id + "/approve"), login(w.approver()), Map.of("actionDigest", digest)), 200);
        body(send(post("/api/v1/action-approvals/" + id + "/confirm"), login(w.owner()), Map.of("actionDigest", digest)), 200);
        MvcResult redeemed = tokenRequest(a.svc, Map.of("grant_type", APPROVED, "approval_id", id, "action_digest", digest,
                "scope", PAY));
        return redeemed.getResponse().getStatus() == 200 ? token(redeemed) : null;
    }

    private void suspend(World w, Agent a) throws Exception {
        body(send(post(lifecycle(w, a) + "/suspend"), w.t().admin, Map.of("reason", "incident")), 200);
    }

    private String lifecycle(World w, Agent a) {
        return base(w.t()) + "/ciam/agent-workloads/" + a.svc.workloadId();
    }
}
