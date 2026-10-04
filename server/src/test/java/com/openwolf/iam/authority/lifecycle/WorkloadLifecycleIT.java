package com.openwolf.iam.authority.lifecycle;

import com.fasterxml.jackson.databind.JsonNode;
import com.openwolf.iam.IamApplication;
import com.openwolf.iam.authority.AuthorityITSupport;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MvcResult;

import java.time.Instant;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;

/**
 * Phase 3.10/3.15: explicit team ownership enforced on every authority path (Phase 1 exchange, standing grants,
 * workload API); owner departure suspends durably; reassignment then reactivation restores; suspension is
 * reversible, retirement terminal with history kept; access reviews are recorded; client-secret rotation keeps exactly
 * the declared overlap; federated workload assertions are denied without a configured provider profile.
 */
@SpringBootTest(classes = IamApplication.class, webEnvironment = SpringBootTest.WebEnvironment.MOCK)
@AutoConfigureMockMvc
class WorkloadLifecycleIT extends AuthorityITSupport {
    static final String STANDING = "urn:openwolf:params:oauth:grant-type:standing-grant";

    record Fixture(Tenant t, Svc agent, String gatewayAud, String ledgerAud, String team, String owner, String grant,
                   String handle) {}

    @Test
    void ownershipIsEnforcedLiveAndOwnerDepartureSuspendsUntilReassignedAndReactivated() throws Exception {
        Fixture f = fixture();
        assertThat(paths(f)).as("unowned workload: Phase 1 behaviour").containsOnly(200);
        body(send(post(lifecycle(f) + "/ownership"), f.t.admin, Map.of("teamId", f.team, "accountablePrincipalId", f.owner)), 200);
        assertThat(paths(f)).containsOnly(200);

        // The accountable owner leaves the team: no authority until ownership is valid again (live check).
        body(send(delete("/teams/" + f.team + "/members/" + f.owner), f.t.admin, null), 204);
        assertThat(paths(f)).doesNotContain(200);
        body(send(post("/teams/" + f.team + "/members"), f.t.admin, Map.of("userId", f.owner)), 201);
        assertThat(paths(f)).containsOnly(200);

        // The owner departs (identity disabled): the workload is suspended durably, even after re-enable.
        body(send(put("/users/" + f.owner), f.t.admin, Map.of("isActive", false)), 200);
        assertThat(status(f)).isEqualTo("SUSPENDED");
        assertThat(paths(f)).doesNotContain(200);
        body(send(put("/users/" + f.owner), f.t.admin, Map.of("isActive", true)), 200);
        assertThat(status(f)).isEqualTo("SUSPENDED");
        assertThat(paths(f)).doesNotContain(200);

        // Reassignment to a valid owner, then explicit reactivation.
        String successor = principal(f.t.id, f.t.s + "-successor", null);
        assertThat(send(post(lifecycle(f) + "/ownership"), f.t.admin, Map.of("teamId", f.team,
                "accountablePrincipalId", successor)).getResponse().getStatus()).as("not a team member").isEqualTo(400);
        body(send(post("/teams/" + f.team + "/members"), f.t.admin, Map.of("userId", successor)), 201);
        body(send(post(lifecycle(f) + "/ownership"), f.t.admin, Map.of("teamId", f.team, "accountablePrincipalId", successor)), 200);
        assertThat(paths(f)).as("still suspended until reactivated").doesNotContain(200);
        body(send(post(lifecycle(f) + "/reactivate"), f.t.admin, null), 200);
        assertThat(paths(f)).containsOnly(200);

        // Team retirement (deletion) removes ownership: authority stops until reassigned.
        body(send(delete("/teams/" + f.team), f.t.admin, null), 204);
        assertThat(paths(f)).doesNotContain(200);
        assertThat(send(post(lifecycle(f) + "/reactivate"), f.t.admin, null).getResponse().getStatus())
                .as("ownership must be reassigned first").isEqualTo(409);
        String newTeam = body(send(post("/teams"), f.t.admin, Map.of("name", f.t.s + "-team2")), 201).path("id").asText();
        body(send(post("/teams/" + newTeam + "/members"), f.t.admin, Map.of("userId", successor)), 201);
        body(send(post(lifecycle(f) + "/ownership"), f.t.admin, Map.of("teamId", newTeam, "accountablePrincipalId", successor)), 200);
        assertThat(paths(f)).containsOnly(200);
        assertThat(jdbc.queryForObject("SELECT count(*) FROM audit_log WHERE resource_id = ? AND action = "
                + "'AGENT_WORKLOAD_SUSPENDED'", Integer.class, f.agent.workloadId())).isEqualTo(1);
    }

    @Test
    void suspensionIsReversibleRetirementIsTerminalAndReviewsAreRecorded() throws Exception {
        Fixture f = fixture();
        assertThat(send(post(lifecycle(f) + "/access-reviews"), f.t.admin, Map.of("decision", "KEEP"))
                .getResponse().getStatus()).as("no valid ownership to keep").isEqualTo(409);
        body(send(post(lifecycle(f) + "/ownership"), f.t.admin, Map.of("teamId", f.team, "accountablePrincipalId", f.owner)), 200);
        JsonNode kept = body(send(post(lifecycle(f) + "/access-reviews"), f.t.admin, Map.of("decision", "KEEP",
                "notes", "quarterly review")), 200);
        assertThat(kept.path("lastReviewedAt").isNull()).isFalse();

        body(send(post(lifecycle(f) + "/suspend"), f.t.admin, Map.of("reason", "incident")), 200);
        assertThat(paths(f)).doesNotContain(200);
        body(send(post(lifecycle(f) + "/reactivate"), f.t.admin, null), 200);
        assertThat(paths(f)).containsOnly(200);

        body(send(post(lifecycle(f) + "/access-reviews"), f.t.admin, Map.of("decision", "RETIRE")), 200);
        assertThat(status(f)).isEqualTo("RETIRED");
        assertThat(paths(f)).doesNotContain(200);
        assertThat(send(post(lifecycle(f) + "/reactivate"), f.t.admin, null).getResponse().getStatus()).isEqualTo(409);
        assertThat(jdbc.queryForObject("SELECT status FROM standing_grants WHERE id = ?::uuid", String.class, f.grant))
                .isEqualTo("REVOKED");
        assertThat(jdbc.queryForObject("SELECT count(*) FROM workload_access_reviews WHERE agent_workload_id = ?::uuid",
                Integer.class, f.agent.workloadId())).isEqualTo(2);
        assertThat(jdbc.queryForObject("SELECT count(*) FROM audit_log WHERE resource_id = ?", Integer.class,
                f.agent.workloadId())).as("history retained").isGreaterThanOrEqualTo(6);
    }

    @Test
    void secretRotationKeepsExactlyTheDeclaredOverlapAndRevocationEndsItAtOnce() throws Exception {
        Fixture f = fixture();
        String second = principal(f.t.id, f.t.s + "-admin2", "tenant_admin");
        String bob = login(second);
        String clientRow = jdbc.queryForObject("SELECT id::text FROM tenant_application_clients WHERE client_id = ?",
                String.class, f.agent.clientId());
        long revision = jdbc.queryForObject("SELECT revision FROM tenant_application_clients WHERE id = ?::uuid",
                Long.class, clientRow);
        JsonNode proposed = body(send(post(base(f.t) + "/identity-control-requests"), f.t.admin, Map.of(
                "action", "ROTATE_APPLICATION_CLIENT_SECRET", "targetType", "APPLICATION_CLIENT", "targetId", clientRow,
                "expectedTargetRevision", revision, "payload", Map.of())), 201);
        String request = base(f.t) + "/identity-control-requests/" + proposed.path("id").asText();
        body(send(post(request + "/approve"), bob, Map.of("expectedRevision", 1)), 200);
        String fresh = body(send(post(request + "/apply"), bob, Map.of("expectedRevision", 2)), 200)
                .path("oneTimeSecret").asText();
        Svc rotated = new Svc(f.agent.clientId(), f.agent.uuid(), fresh, f.agent.audience(), f.agent.appId(),
                f.agent.workloadId(), f.agent.workloadRef());

        assertThat(cc(f.agent).getResponse().getStatus()).as("old secret inside the overlap").isEqualTo(200);
        assertThat(cc(rotated).getResponse().getStatus()).as("new secret").isEqualTo(200);
        assertThat(cc(new Svc(f.agent.clientId(), null, "wrong-" + fresh, null, null, null, null)).getResponse()
                .getStatus()).isEqualTo(401);
        Thread.sleep(5500);
        assertThat(cc(f.agent).getResponse().getStatus()).as("old secret after the overlap").isEqualTo(401);
        assertThat(cc(rotated).getResponse().getStatus()).isEqualTo(200);
        assertThat(jdbc.queryForObject("SELECT count(*) FROM audit_log WHERE tenant_id = ? AND "
                + "(coalesce(after_state::text,'') || coalesce(before_state::text,'')) LIKE ?", Integer.class, f.t.id,
                "%" + fresh + "%")).isZero();
    }

    @Test
    void federatedAssertionsAreDeniedWithoutAConfiguredProviderProfile() throws Exception {
        Fixture f = fixture();
        body(send(post(lifecycle(f) + "/federation-bindings"), f.t.admin, Map.of("providerProfile", "hosted-x",
                "issuer", "https://issuer.invalid", "subject", "workload-1")), 201);
        MvcResult r = mvc.perform(post("/oauth/token").contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .param("grant_type", "client_credentials").param("scope", READ).param("client_id", f.agent.clientId())
                .param("client_assertion_type", "urn:openwolf:params:oauth:client-assertion-type:workload-federation")
                .param("client_assertion_profile", "hosted-x")
                .param("client_assertion", Base64.getUrlEncoder().encodeToString("anything".getBytes()))).andReturn();
        assertThat(r.getResponse().getStatus()).isEqualTo(401);
        assertThat(r.getResponse().getContentAsString()).contains("invalid_client").doesNotContain("access_token");
    }

    // =================================================================================================================

    /**
     * Four authority paths: client-credentials issuance, Phase 1 workload→Gateway exchange, standing-grant renewal,
     * workload API. The last-issued client-credentials token is reused when issuance is refused (Phase 3.15).
     */
    private List<Integer> paths(Fixture f) throws Exception {
        MvcResult issued = cc(f.agent);
        int issuance = issued.getResponse().getStatus();
        if (issuance == 200) lastCc = token(issued);
        String cc = lastCc;
        int exchange = exchange(f.agent, cc, f.gatewayAud, READ, Map.of()).getResponse().getStatus();
        MvcResult renewed = tokenRequest(f.agent, Map.of("grant_type", STANDING, "standing_grant", f.grant,
                "renewal_handle", currentHandle(f), "scope", READ));
        int renewal = renewed.getResponse().getStatus();
        if (renewal == 200) handles.put(f.grant, tokenResponse(renewed).path("renewal_handle").asText());
        int api = send(post("/api/v1/workload/tasks"), cc, Map.of("authorityType", "STANDING_GRANT",
                "authorityId", f.grant, "taskRef", "t-" + UUID.randomUUID().toString().substring(0, 6)))
                .getResponse().getStatus();
        return List.of(issuance, exchange, renewal == 200 ? 200 : renewal, api == 201 ? 200 : api);
    }

    private String lastCc;

    private final Map<String, String> handles = new HashMap<>();

    /** Renewal rotates the handle; keep the latest one per grant (failed renewals leave it unchanged). */
    private String currentHandle(Fixture f) {
        return handles.getOrDefault(f.grant, f.handle);
    }

    private MvcResult cc(Svc client) throws Exception {
        return mvc.perform(post("/oauth/token").contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .header(HttpHeaders.AUTHORIZATION, basic(client)).param("grant_type", "client_credentials")
                .param("scope", READ)).andReturn();
    }

    private Fixture fixture() throws Exception {
        Tenant t = tenant("p3e-l");
        Svc agent = workload(t, "agent", List.of(READ));
        String gatewayAud = "gw:" + t.id + ":" + t.s;
        Svc broker = confidential(t, app(t, "gw", gatewayAud), gatewayAud, t.s + "-broker", List.of(READ));
        body(send(post(base(t) + "/agent-exchange/brokers"), t.admin, Map.of("oauthClientId", broker.clientId(),
                "gatewayAudience", gatewayAud, "scopes", List.of(READ))), 201);
        route(t, agent.workloadId(), "GATEWAY", null, gatewayAud, List.of(READ));
        String ledgerAud = "ledger:" + t.id + ":" + t.s;
        app(t, "ledger", ledgerAud);
        route(t, agent.workloadId(), "RESOURCE", null, ledgerAud, List.of(READ));
        String owner = principal(t.id, t.s + "-owner", null);
        entitle(t, agent.appId(), owner, List.of(READ));
        String team = body(send(post("/teams"), t.admin, Map.of("name", t.s + "-team")), 201).path("id").asText();
        body(send(post("/teams/" + team + "/members"), t.admin, Map.of("userId", owner)), 201);
        String grant = body(send(post("/api/me/standing-grants"), login(owner), Map.of("agentWorkloadId",
                agent.workloadId(), "audience", ledgerAud, "scopes", List.of(READ), "purpose", "Nightly",
                "expiresAt", Instant.now().plusSeconds(1800).toString())), 201).path("id").asText();
        String handle = tokenResponse(tokenRequest(agent, Map.of("grant_type", STANDING, "standing_grant", grant,
                "scope", READ))).path("renewal_handle").asText();
        Fixture f = new Fixture(t, agent, gatewayAud, ledgerAud, team, owner, grant, handle);
        return f;
    }

    private String lifecycle(Fixture f) { return base(f.t) + "/ciam/agent-workloads/" + f.agent.workloadId(); }

    private String status(Fixture f) {
        return jdbc.queryForObject("SELECT status FROM agent_workload_identities WHERE id = ?::uuid", String.class,
                f.agent.workloadId());
    }
}
