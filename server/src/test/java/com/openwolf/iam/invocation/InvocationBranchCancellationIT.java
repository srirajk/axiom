package com.openwolf.iam.invocation;

import com.fasterxml.jackson.databind.JsonNode;
import com.openwolf.iam.IamApplication;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MvcResult;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;

/**
 * Phase 3.6 branch cancellation (and 3.4 tasks bound to an invocation context): the establishing broker cancels one
 * branch; it and its descendants stop, while its sibling, the root run, another run of the same session and the human
 * session continue. Cancellation is distinct from revocation, permanent, idempotent and serialized with branch
 * creation. Only the establishing broker may cancel.
 */
@SpringBootTest(classes = IamApplication.class, webEnvironment = SpringBootTest.WebEnvironment.MOCK)
@AutoConfigureMockMvc
@Import(SyntheticInvocationAuthorizationVerifier.Config.class)
class InvocationBranchCancellationIT extends InvocationContextITSupport {

    @Test
    void cancellingABranchStopsItsDescendantsOnly() throws Exception {
        World w = world("icx-c");
        Entry e = enter(w, "claims", member(w, "claims"));
        Established root = establish(w, e, Map.of("invocation_run", "run-1"));
        Established otherRun = establish(w, e, Map.of("invocation_run", "run-2"));
        String b0 = token(exchange(w.agent, root.token(), w.gatewayAud, SCOPE, Map.of("invocation_branch", "b0")));
        String b1 = token(exchange(w.agent, root.token(), w.gatewayAud, SCOPE, Map.of("invocation_branch", "b1")));
        // A nested branch under b0, created at the broker hop (the fixture bounds token depth at 2).
        String b00 = token(exchange(w.broker, b0, w.agent2Aud, SCOPE, Map.of("invocation_branch", "b00")));
        String b0Id = (String) claims(b0).get("ctx");
        String b00Id = (String) claims(b00).get("ctx");
        assertThat(row(b00Id).get("parent_id").toString()).isEqualTo(b0Id);
        assertThat(introspect(w.agent2, b00).path("active").asBoolean()).isTrue();

        assertThat(cancel(clientCredentials(w.agent), b0Id).getResponse().getStatus())
                .as("only the establishing broker may cancel").isEqualTo(403);
        JsonNode cancelled = body(cancel(clientCredentials(w.broker), b0Id), 200);
        assertThat(cancelled.path("cancelled_contexts").asInt()).isEqualTo(2);
        assertThat(body(cancel(clientCredentials(w.broker), b0Id), 200).path("cancelled_contexts").asInt())
                .as("idempotent").isZero();

        denied(exchange(w.broker, b0, w.toolAud, SCOPE, Map.of()), "invalid_grant");
        assertThat(introspect(w.agent2, b00).path("active").asBoolean()).as("descendant stops").isFalse();
        token(exchange(w.broker, b1, w.toolAud, SCOPE, Map.of()));
        token(exchange(w.agent, root.token(), w.gatewayAud, SCOPE, Map.of()));
        token(exchange(w.agent, otherRun.token(), w.gatewayAud, SCOPE, Map.of()));
        assertThat(introspect(w.broker, e.p1()).path("active").asBoolean()).as("human session continues").isTrue();
        assertThat(row(b0Id)).containsEntry("status", "CANCELLED");
        assertThat(row(b00Id)).containsEntry("status", "CANCELLED");
        assertThat(row(root.contextId())).containsEntry("status", "ACTIVE");
        assertThat(row(b0Id).get("revoked_at")).as("cancellation is not revocation").isNull();
        // An administrator's later revocation does not re-version or convert a cancelled branch.
        body(revokeContext(w, b0Id), 200);
        assertThat(row(b0Id)).containsEntry("status", "CANCELLED");
        assertThat(jdbc.queryForObject("SELECT count(*) FROM audit_log WHERE action = 'INVOCATION_CONTEXT_CANCELLED' "
                + "AND resource_id = ?", Integer.class, b0Id)).isEqualTo(1);
    }

    @Test
    void cancellationIsSerializedWithBranchCreation() throws Exception {
        World w = world("icx-c");
        Established root = establish(w, enter(w, "claims", member(w, "claims")), Map.of());
        String b1 = token(exchange(w.agent, root.token(), w.gatewayAud, SCOPE, Map.of("invocation_branch", "b1")));
        String b1Id = (String) claims(b1).get("ctx");
        String broker = clientCredentials(w.broker);
        List<MvcResult> results = InvocationContextEstablishmentIT.parallel(2, i -> i == 0 ? cancel(broker, b1Id)
                : exchange(w.broker, b1, w.agent2Aud, SCOPE, Map.of("invocation_branch", "b10")));
        assertThat(results.get(0).getResponse().getStatus()).isEqualTo(200);
        assertThat(jdbc.queryForObject("SELECT count(*) FROM invocation_contexts WHERE parent_id = ?::uuid "
                + "AND status = 'ACTIVE'", Integer.class, b1Id)).as("no live child under a cancelled branch").isZero();
        if (results.get(1).getResponse().getStatus() == 200) {
            assertThat(introspect(w.agent2, token(results.get(1))).path("active").asBoolean()).isFalse();
        }
    }

    @Test
    void aTaskBoundToARunResumesOnlyWhileTheRunIsCurrent() throws Exception {
        World w = world("icx-c");
        Established root = establish(w, enter(w, "claims", member(w, "claims")), Map.of());
        String agent = clientCredentials(w.agent);
        JsonNode task = body(send(post("/api/v1/workload/tasks"), agent, Map.of("authorityType", "INVOCATION_CONTEXT",
                "authorityId", root.contextId(), "taskRef", "run-task")), 201);
        assertThat(task.path("ownerSubject").asText()).isEqualTo(root.entry().user());
        assertThat(send(post("/api/v1/workload/tasks"), clientCredentials(w.agent2), Map.of("authorityType",
                "INVOCATION_CONTEXT", "authorityId", root.contextId())).getResponse().getStatus())
                .as("the run was not established for this Agent").isEqualTo(403);
        String taskId = task.path("id").asText();
        body(send(post("/api/v1/workload/tasks/" + taskId + "/resume"), agent, null), 200);
        body(cancel(clientCredentials(w.broker), root.contextId()), 200);
        assertThat(send(post("/api/v1/workload/tasks/" + taskId + "/resume"), agent, null).getResponse().getStatus())
                .isEqualTo(403);
    }

    private String clientCredentials(Svc client) throws Exception {
        return token(mvc.perform(post("/oauth/token").contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .header(HttpHeaders.AUTHORIZATION, basic(client)).param("grant_type", "client_credentials")
                .param("scope", SCOPE)).andReturn());
    }

    private MvcResult cancel(String bearer, String contextId) throws Exception {
        return send(post("/api/v1/workload/invocation-contexts/" + contextId + "/cancel"), bearer,
                Map.of("reason", "branch no longer needed"));
    }
}
