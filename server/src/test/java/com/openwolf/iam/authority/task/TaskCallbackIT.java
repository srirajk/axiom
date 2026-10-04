package com.openwolf.iam.authority.task;

import com.openwolf.iam.IamApplication;
import com.openwolf.iam.authority.AuthorityITSupport;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MvcResult;

import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;

/**
 * Phase 3.5 with a (synthetic, test-only) trust anchor: a callback is accepted once, only for the task, provider,
 * tenant audience, time, nonce, event and body it was signed for; unsigned, tampered, replayed, stale, wrong-task,
 * wrong-tenant, unbound-provider and ended-task callbacks change nothing, and no callback resumes work.
 */
@SpringBootTest(classes = IamApplication.class, webEnvironment = SpringBootTest.WebEnvironment.MOCK)
@AutoConfigureMockMvc
@Import(SyntheticTaskCallbackVerifier.Config.class)
class TaskCallbackIT extends AuthorityITSupport {
    static final String GRANT = "urn:openwolf:params:oauth:grant-type:standing-grant";

    @Test
    void onlyAnAuthenticFreshUnreplayedCallbackForTheBoundTaskIsAccepted() throws Exception {
        Tenant t = tenant("p3c-cb");
        Svc agent = workload(t, "agent", List.of(READ));
        String ledgerAud = "ledger:" + t.id + ":" + t.s;
        app(t, "ledger", ledgerAud);
        route(t, agent.workloadId(), "RESOURCE", null, ledgerAud, List.of(READ));
        String owner = principal(t.id, t.s + "-owner", null);
        entitle(t, agent.appId(), owner, List.of(READ));
        String grantId = body(send(post("/api/me/standing-grants"), login(owner), Map.of("agentWorkloadId",
                agent.workloadId(), "audience", ledgerAud, "scopes", List.of(READ), "purpose", "Nightly",
                "expiresAt", Instant.now().plusSeconds(1800).toString())), 201).path("id").asText();
        tokenResponse(tokenRequest(agent, Map.of("grant_type", GRANT, "standing_grant", grantId, "scope", READ)));
        String agentToken = clientCredentials(agent, READ);
        UUID task = UUID.fromString(body(send(post("/api/v1/workload/tasks"), agentToken, Map.of("authorityType",
                "STANDING_GRANT", "authorityId", grantId, "taskRef", "cb-1", "callbackProvider", "provider-a")), 201)
                .path("id").asText());
        UUID otherTask = UUID.fromString(body(send(post("/api/v1/workload/tasks"), agentToken, Map.of("authorityType",
                "STANDING_GRANT", "authorityId", grantId, "taskRef", "cb-2")), 201).path("id").asText());

        byte[] body = "{\"status\":\"done\"}".getBytes();
        var good = claim(t.id, "provider-a", task, Instant.now(), "nonce-" + UUID.randomUUID(), body);
        assertThat(callback(t.id, task, good, body, SyntheticTaskCallbackVerifier.sign(good)).getResponse().getStatus())
                .isEqualTo(202);
        assertThat(callback(t.id, task, good, body, SyntheticTaskCallbackVerifier.sign(good)).getResponse().getStatus())
                .as("replay").isEqualTo(409);

        var fresh = claim(t.id, "provider-a", task, Instant.now(), "nonce-" + UUID.randomUUID(), body);
        String signature = SyntheticTaskCallbackVerifier.sign(fresh);
        assertThat(callback(t.id, task, fresh, body, null).getResponse().getStatus()).as("unsigned").isEqualTo(401);
        assertThat(callback(t.id, task, fresh, "{\"status\":\"paid\"}".getBytes(), signature).getResponse().getStatus())
                .as("tampered body").isEqualTo(401);
        assertThat(callback(t.id, otherTask, fresh, body, signature).getResponse().getStatus()).as("wrong task").isEqualTo(401);
        var stale = claim(t.id, "provider-a", task, Instant.now().minusSeconds(600), "nonce-" + UUID.randomUUID(), body);
        assertThat(callback(t.id, task, stale, body, SyntheticTaskCallbackVerifier.sign(stale)).getResponse().getStatus())
                .as("stale").isEqualTo(401);
        var foreign = claim("p3c-other", "provider-a", task, Instant.now(), "nonce-" + UUID.randomUUID(), body);
        assertThat(callback(t.id, task, foreign, body, SyntheticTaskCallbackVerifier.sign(foreign)).getResponse().getStatus())
                .as("signed for another tenant's audience").isEqualTo(401);
        var unbound = claim(t.id, "provider-b", task, Instant.now(), "nonce-" + UUID.randomUUID(), body);
        assertThat(callback(t.id, task, unbound, body, SyntheticTaskCallbackVerifier.sign(unbound)).getResponse().getStatus())
                .as("provider not bound to the task").isEqualTo(403);

        assertThat(jdbc.queryForMap("SELECT status, callback_count, resume_count FROM durable_tasks WHERE id = ?", task))
                .containsEntry("status", "ACTIVE").containsEntry("callback_count", 1).containsEntry("resume_count", 0);

        body(send(post("/api/v1/workload/tasks/" + task + "/complete"), agentToken, null), 200);
        var late = claim(t.id, "provider-a", task, Instant.now(), "nonce-" + UUID.randomUUID(), body);
        assertThat(callback(t.id, task, late, body, SyntheticTaskCallbackVerifier.sign(late)).getResponse().getStatus())
                .as("ended task").isEqualTo(409);
        assertThat(auditText(t.id)).doesNotContain(signature);
    }

    private static TaskCallbackVerifier.CallbackClaim claim(String tenant, String provider, UUID task, Instant at,
                                                            String nonce, byte[] body) {
        return new TaskCallbackVerifier.CallbackClaim(tenant, provider, task, TaskCallbackService.audience(tenant),
                Instant.ofEpochSecond(at.getEpochSecond()), nonce, "task.completed", TaskCallbackService.sha256(body));
    }

    private MvcResult callback(String tenant, UUID task, TaskCallbackVerifier.CallbackClaim claim, byte[] body,
                           String signature) throws Exception {
        var request = org.springframework.test.web.servlet.request.MockMvcRequestBuilders
                .post("/api/v1/callbacks/tenants/" + tenant + "/tasks/" + task)
                .contentType(MediaType.APPLICATION_JSON).content(body)
                .header("X-Axiom-Callback-Provider", claim.provider())
                .header("X-Axiom-Callback-Timestamp", claim.issuedAt().getEpochSecond())
                .header("X-Axiom-Callback-Nonce", claim.nonce())
                .header("X-Axiom-Callback-Event", claim.eventType());
        if (signature != null) request = request.header("X-Axiom-Callback-Signature", signature);
        return mvc.perform(request).andReturn();
    }
}
