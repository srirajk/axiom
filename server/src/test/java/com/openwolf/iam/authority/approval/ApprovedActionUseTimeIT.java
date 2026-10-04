package com.openwolf.iam.authority.approval;

import com.fasterxml.jackson.databind.JsonNode;
import com.openwolf.iam.IamApplication;
import com.openwolf.iam.authority.AuthorityITSupport;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;

import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;

/**
 * Phase 3.8 use-time validation (repair): an issued approved-action token is valid only while everything that
 * authorized its redemption still holds — the Agent workload and its OAuth client, the server-owned route to the
 * receiver, and the initiator's permission for the approved scopes. Each change makes introspection inactive for the
 * affected token only; an unrelated token (other workload, other route, other permission) stays active.
 */
@SpringBootTest(classes = IamApplication.class, webEnvironment = SpringBootTest.WebEnvironment.MOCK)
@AutoConfigureMockMvc
class ApprovedActionUseTimeIT extends AuthorityITSupport {
    static final String GRANT = "urn:openwolf:params:oauth:grant-type:approved-action";

    record Fixture(Tenant t, Svc agent, Svc other, Svc receiver, String receiverAud, String agentRoute,
                   String otherRoute, String initiator, String approver, String membership, String payRole) {}

    @Test
    void suspendingTheWorkloadStopsItsTokenOnly() throws Exception {
        Fixture f = fixture();
        String affected = approvedToken(f, f.agent, PAY);
        String unrelated = approvedToken(f, f.other, PAY);
        body(send(post(base(f.t) + "/ciam/agent-workloads/" + f.agent.workloadId() + "/suspend"), f.t.admin,
                Map.of("reason", "incident")), 200);
        assertActive(f, affected, false);
        assertActive(f, unrelated, true);
    }

    @Test
    void disablingTheWorkloadClientStopsItsTokenOnly() throws Exception {
        Fixture f = fixture();
        String affected = approvedToken(f, f.agent, PAY);
        String unrelated = approvedToken(f, f.other, PAY);
        body(send(delete(base(f.t) + "/applications/" + f.agent.appId() + "/clients/" + f.agent.uuid()), f.t.admin,
                null), 204);
        assertActive(f, affected, false);
        assertActive(f, unrelated, true);
    }

    @Test
    void revokingTheRouteStopsItsTokenOnly() throws Exception {
        Fixture f = fixture();
        String affected = approvedToken(f, f.agent, PAY);
        String unrelated = approvedToken(f, f.other, PAY);
        body(send(post(base(f.t) + "/agent-exchange/routes/" + f.agentRoute + "/revoke"), f.t.admin, null), 200);
        assertActive(f, affected, false);
        assertActive(f, unrelated, true);
    }

    @Test
    void removingTheInitiatorsPermissionStopsTokensThatNeedItOnly() throws Exception {
        Fixture f = fixture();
        String affected = approvedToken(f, f.agent, PAY);
        String unrelated = approvedToken(f, f.agent, READ);
        body(send(delete(base(f.t) + "/applications/" + f.agent.appId() + "/access/memberships/" + f.membership
                + "/roles/" + f.payRole), f.t.admin, null), 200);
        assertActive(f, affected, false);
        assertActive(f, unrelated, true);
    }

    @Test
    void disablingTheInitiatorsMembershipStopsAllTheirApprovedActionTokens() throws Exception {
        Fixture f = fixture();
        String pay = approvedToken(f, f.agent, PAY);
        String read = approvedToken(f, f.other, READ);
        body(send(delete(base(f.t) + "/applications/" + f.agent.appId() + "/access/memberships/" + f.membership),
                f.t.admin, null), 204);
        assertActive(f, pay, false);
        assertActive(f, read, false);
    }

    // =================================================================================================================

    private Fixture fixture() throws Exception {
        Tenant t = tenant("p3r-u");
        // Both Agents are clients of one Use Case application, so the initiator's entitlement covers both.
        String audience = "agent:" + t.id + ":" + t.s + "-uc";
        String appId = app(t, "uc", audience);
        Svc agent = registered(t, appId, audience, t.s + "-agent");
        Svc other = registered(t, appId, audience, t.s + "-other");
        String receiverAud = "payments:" + t.id + ":" + t.s;
        String receiverApp = app(t, "payments", receiverAud);
        Svc receiver = confidential(t, receiverApp, receiverAud, t.s + "-payments", List.of(READ));
        String agentRoute = route(t, agent.workloadId(), "RESOURCE", null, receiverAud, List.of(READ, PAY));
        String otherRoute = route(t, other.workloadId(), "RESOURCE", null, receiverAud, List.of(READ, PAY));
        String initiator = principal(t.id, t.s + "-initiator", null);
        String approver = principal(t.id, t.s + "-approver", ActionApprovalService.APPROVER_ROLE);
        String access = base(t) + "/applications/" + appId + "/access";
        String readRole = role(t, access, Map.of(READ, "allow"));
        String payRole = role(t, access, Map.of(PAY, "cosign"));
        String membership = body(send(post(access + "/memberships"), t.admin, Map.of("principalId", initiator,
                "assignmentSource", "p3-test")), 201).get("id").asText();
        for (String r : List.of(readRole, payRole)) {
            body(send(post(access + "/memberships/" + membership + "/roles"), t.admin, Map.of("roleId", r,
                    "assignmentSource", "p3-test")), 200);
        }
        return new Fixture(t, agent, other, receiver, receiverAud, agentRoute, otherRoute, initiator, approver,
                membership, payRole);
    }

    private Svc registered(Tenant t, String appId, String audience, String clientId) throws Exception {
        Svc svc = confidential(t, appId, audience, clientId, List.of(READ, PAY));
        String ref = "agent:" + clientId + ":test";
        String id = body(send(post(base(t) + "/ciam/agent-workloads"), t.admin, Map.of("workloadRef", ref,
                "name", clientId, "oauthClientId", clientId)), 201).get("id").asText();
        return new Svc(svc.clientId(), svc.uuid(), svc.secret(), audience, appId, id, ref);
    }

    private String role(Tenant t, String access, Map<String, String> effects) throws Exception {
        return body(send(post(access + "/roles"), t.admin, Map.of("roleKey", t.s + "-r" + UUID.randomUUID().toString()
                .substring(0, 6), "displayName", "Role", "permissions", List.copyOf(effects.keySet()),
                "permissionEffects", effects)), 201).get("id").asText();
    }

    /** Request → independent approval → step-up confirmation → single redemption; returns the issued token. */
    private String approvedToken(Fixture f, Svc agent, String scope) throws Exception {
        JsonNode requested = body(send(post("/api/v1/action-approvals"), login(f.initiator), Map.of("agentWorkloadId",
                agent.workloadId(), "receiverAudience", f.receiverAud, "scopes", List.of(scope),
                "actionType", "payment.execute", "action", json.readTree("{\"invoice\":\"INV-" + UUID.randomUUID()
                        + "\",\"amount\":{\"currency\":\"GBP\",\"minor\":100}}"),
                "deadlineSeconds", 900, "maxAuthAgeSeconds", 60)), 201);
        String id = requested.path("id").asText();
        String digest = requested.path("actionDigest").asText();
        body(send(post("/api/v1/action-approvals/" + id + "/approve"), login(f.approver), Map.of("actionDigest", digest)), 200);
        body(send(post("/api/v1/action-approvals/" + id + "/confirm"), login(f.initiator), Map.of("actionDigest", digest)), 200);
        String token = token(tokenRequest(agent, Map.of("grant_type", GRANT, "approval_id", id, "action_digest", digest,
                "scope", scope)));
        assertActive(f, token, true);
        return token;
    }

    private void assertActive(Fixture f, String token, boolean expected) throws Exception {
        assertThat(introspect(f.receiver, token).path("active").asBoolean())
                .as("approved-action token for %s", claims(token).get("act")).isEqualTo(expected);
    }
}
