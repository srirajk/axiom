package com.openwolf.iam.authority.task;

import com.fasterxml.jackson.databind.JsonNode;
import com.openwolf.iam.IamApplication;
import com.openwolf.iam.authority.AuthorityITSupport;
import org.junit.jupiter.api.Test;
import org.springframework.boot.WebApplicationType;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;

/**
 * Phase 3.4 durable tasks bound to standing authority, and the production default of 3.5 (no callback trust anchor):
 * resume re-checks current authority; cancellation is persistent across restart; a cancelled task cannot renew
 * authority through its task binding; withdrawn authority refuses resume; callbacks are denied by default.
 */
@SpringBootTest(classes = IamApplication.class, webEnvironment = SpringBootTest.WebEnvironment.MOCK)
@AutoConfigureMockMvc
class DurableTaskIT extends AuthorityITSupport {
    static final String GRANT = "urn:openwolf:params:oauth:grant-type:standing-grant";

    record Fixture(Tenant t, Svc agent, Svc other, String owner, String grantId, String handle) {}

    @Test
    void resumeRechecksAuthorityAndCancellationIsPermanentAcrossRestart() throws Exception {
        Fixture f = fixture();
        String agentToken = clientCredentials(f.agent, READ);
        JsonNode task = body(createTask(agentToken, f.grantId, "nightly-1", "provider-a"), 201);
        String taskId = task.path("id").asText();
        assertThat(task.path("authorityVersion").asLong()).isEqualTo(1);
        assertThat(task.path("ownerSubject").asText()).isEqualTo(f.owner);
        assertThat(body(createTask(agentToken, f.grantId, "nightly-1", "provider-a"), 201).path("id").asText())
                .as("same reference, same task").isEqualTo(taskId);
        assertThat(body(send(post("/api/v1/workload/tasks/" + taskId + "/resume"), agentToken, null), 200)
                .path("resumeCount").asInt()).isEqualTo(1);
        assertThat(send(post("/api/v1/workload/tasks/" + taskId + "/resume"), clientCredentials(f.other, READ), null)
                .getResponse().getStatus()).as("another workload").isEqualTo(404);

        // Renewal bound to the task carries the task; cancelling the task stops that binding but not the grant.
        JsonNode bound = tokenResponse(redeem(f.agent, f.grantId, f.handle, READ, taskId));
        assertThat(claims(bound.path("access_token").asText())).containsEntry("task_id", taskId);
        body(send(post("/api/me/tasks/" + taskId + "/cancel"), login(f.owner), Map.of("reason", "owner stopped it")), 200);
        assertThat(send(post("/api/v1/workload/tasks/" + taskId + "/resume"), agentToken, null).getResponse().getStatus())
                .isEqualTo(409);
        assertThat(introspect(f.agent, bound.path("access_token").asText()).path("active").asBoolean()).isFalse();
        String handle = bound.path("renewal_handle").asText();
        denied(redeem(f.agent, f.grantId, handle, READ, taskId), "invalid_grant");
        handle = tokenResponse(redeem(f.agent, f.grantId, handle, READ, null)).path("renewal_handle").asText();

        String second = body(createTask(agentToken, f.grantId, "nightly-2", null), 201).path("id").asText();
        try (ConfigurableApplicationContext restarted = new SpringApplicationBuilder(IamApplication.class)
                .web(WebApplicationType.SERVLET).run(commandLine())) {
            MockMvc fresh = MockMvcBuilders.webAppContextSetup((WebApplicationContext) restarted).apply(springSecurity()).build();
            assertThat(fresh.perform(post("/api/v1/workload/tasks/" + taskId + "/resume")
                    .header(HttpHeaders.AUTHORIZATION, "Bearer " + agentToken)).andReturn().getResponse().getStatus())
                    .as("restart cannot revive a cancelled task").isEqualTo(409);
            assertThat(fresh.perform(post("/api/v1/workload/tasks/" + second + "/resume")
                    .header(HttpHeaders.AUTHORIZATION, "Bearer " + agentToken)).andReturn().getResponse().getStatus())
                    .isEqualTo(200);
        }

        // Withdrawn authority refuses every resume and every new binding.
        body(send(post(base(f.t) + "/standing-grants/" + f.grantId + "/revoke"), f.t.admin, Map.of("reason", "x")), 200);
        assertThat(send(post("/api/v1/workload/tasks/" + second + "/resume"), agentToken, null).getResponse().getStatus())
                .isEqualTo(403);
        assertThat(createTask(agentToken, f.grantId, "nightly-3", null).getResponse().getStatus()).isEqualTo(403);
        assertThat(jdbc.queryForObject("SELECT status FROM durable_tasks WHERE id = ?::uuid", String.class, second))
                .isEqualTo("ACTIVE");
        assertThat(auditText(f.t.id)).doesNotContain(handle);
    }

    @Test
    void workloadApiAcceptsOnlyAWorkloadsOwnClientCredentialsToken() throws Exception {
        Fixture f = fixture();
        assertThat(createTask(login(f.owner), f.grantId, "x", null).getResponse().getStatus()).isEqualTo(401);
        assertThat(createTask(f.t.admin, f.grantId, "x", null).getResponse().getStatus()).isEqualTo(401);
        String standingToken = tokenResponse(redeem(f.agent, f.grantId, f.handle, READ, null)).path("access_token").asText();
        assertThat(createTask(standingToken, f.grantId, "x", null).getResponse().getStatus())
                .as("a delegated token is not the workload's own identity").isEqualTo(401);
        assertThat(createTask(clientCredentials(f.other, READ), f.grantId, "x", null).getResponse().getStatus())
                .as("another workload cannot bind this grant").isEqualTo(403);
    }

    @Test
    void callbacksAreRejectedWithoutAConfiguredTrustAnchor() throws Exception {
        Fixture f = fixture();
        String taskId = body(createTask(clientCredentials(f.agent, READ), f.grantId, "cb", "provider-a"), 201)
                .path("id").asText();
        byte[] body = "{\"status\":\"done\"}".getBytes();
        TaskCallbackVerifier.CallbackClaim claim = new TaskCallbackVerifier.CallbackClaim(f.t.id, "provider-a",
                UUID.fromString(taskId), TaskCallbackService.audience(f.t.id), Instant.now(), "nonce-" + UUID.randomUUID(),
                "task.completed", TaskCallbackService.sha256(body));
        MvcResult r = mvc.perform(post("/api/v1/callbacks/tenants/" + f.t.id + "/tasks/" + taskId)
                .contentType(MediaType.APPLICATION_JSON).content(body)
                .header("X-Axiom-Callback-Provider", claim.provider())
                .header("X-Axiom-Callback-Timestamp", claim.issuedAt().getEpochSecond())
                .header("X-Axiom-Callback-Nonce", claim.nonce())
                .header("X-Axiom-Callback-Event", claim.eventType())
                .header("X-Axiom-Callback-Signature", SyntheticTaskCallbackVerifier.sign(claim))).andReturn();
        assertThat(r.getResponse().getStatus()).isEqualTo(401);
        assertThat(jdbc.queryForObject("SELECT callback_count FROM durable_tasks WHERE id = ?::uuid", Integer.class, taskId))
                .isZero();
    }

    // =================================================================================================================

    private Fixture fixture() throws Exception {
        Tenant t = tenant("p3c-t");
        Svc agent = workload(t, "agent", List.of(READ, WRITE));
        Svc other = workload(t, "other", List.of(READ, WRITE));
        String ledgerAud = "ledger:" + t.id + ":" + t.s;
        app(t, "ledger", ledgerAud);
        route(t, agent.workloadId(), "RESOURCE", null, ledgerAud, List.of(READ));
        String owner = principal(t.id, t.s + "-owner", null);
        entitle(t, agent.appId(), owner, List.of(READ));
        String grantId = body(send(post("/api/me/standing-grants"), login(owner), Map.of("agentWorkloadId",
                agent.workloadId(), "audience", ledgerAud, "scopes", List.of(READ), "purpose", "Nightly",
                "expiresAt", Instant.now().plusSeconds(1800).toString())), 201).path("id").asText();
        String handle = tokenResponse(redeem(agent, grantId, null, READ, null)).path("renewal_handle").asText();
        return new Fixture(t, agent, other, owner, grantId, handle);
    }

    private MvcResult createTask(String bearer, String grantId, String ref, String provider) throws Exception {
        Map<String, Object> request = new HashMap<>(Map.of("authorityType", "STANDING_GRANT", "authorityId", grantId,
                "taskRef", ref));
        if (provider != null) request.put("callbackProvider", provider);
        return send(post("/api/v1/workload/tasks"), bearer, request);
    }

    private MvcResult redeem(Svc client, String grantId, String handle, String scope, String taskId) throws Exception {
        Map<String, String> params = new HashMap<>(Map.of("grant_type", GRANT, "standing_grant", grantId, "scope", scope));
        if (handle != null) params.put("renewal_handle", handle);
        if (taskId != null) params.put("task_id", taskId);
        return tokenRequest(client, params);
    }
}
