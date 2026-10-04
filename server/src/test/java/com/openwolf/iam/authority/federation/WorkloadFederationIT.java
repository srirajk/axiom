package com.openwolf.iam.authority.federation;

import com.openwolf.iam.IamApplication;
import com.openwolf.iam.authority.AuthorityITSupport;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;

import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;

/**
 * Phase 3.12 with a (synthetic, test-only) provider profile: a federated assertion authenticates exactly the bound
 * workload's client and yields only that workload's identity. It cannot select another workload, invent a human
 * subject, be replayed, be used after expiry, outside its audience or after the binding or workload stops, and the
 * federated workload cannot redeem another workload's authority.
 */
@SpringBootTest(classes = IamApplication.class, webEnvironment = SpringBootTest.WebEnvironment.MOCK)
@AutoConfigureMockMvc
@Import(SyntheticWorkloadAssertionVerifier.Config.class)
class WorkloadFederationIT extends AuthorityITSupport {
    static final String ISSUER = "https://hosted-platform.invalid";
    static final String AUDIENCE = "http://localhost:8084/oauth/token";

    @Test
    void anAssertionAuthenticatesOnlyItsBoundWorkload() throws Exception {
        Tenant t = tenant("p3e-f");
        Svc agent = workload(t, "hosted", List.of(READ));
        Svc other = workload(t, "other", List.of(READ));
        String subject = "workload/" + UUID.randomUUID();
        String binding = body(send(post(base(t) + "/ciam/agent-workloads/" + agent.workloadId() + "/federation-bindings"),
                t.admin, Map.of("providerProfile", SyntheticWorkloadAssertionVerifier.PROFILE, "issuer", ISSUER,
                        "subject", subject)), 201).path("id").asText();
        assertThat(send(post(base(t) + "/ciam/agent-workloads/" + other.workloadId() + "/federation-bindings"), t.admin,
                Map.of("providerProfile", SyntheticWorkloadAssertionVerifier.PROFILE, "issuer", ISSUER, "subject", subject))
                .getResponse().getStatus()).as("one external identity, one workload").isEqualTo(409);

        Map<String, Object> human = new HashMap<>(claims(subject, AUDIENCE, 60));
        human.put("represented_user", "alice@customer.invalid");
        human.put("act_as", "alice");
        String token = token(federated(agent.clientId(), SyntheticWorkloadAssertionVerifier.issue(human)));
        Map<String, Object> c = claims(token);
        assertThat(c).containsEntry("sub", agent.clientId()).containsEntry("identity_kind", "workload")
                .containsEntry("client_id", agent.clientId()).doesNotContainKeys("act", "represented_user", "act_as");

        String replayed = SyntheticWorkloadAssertionVerifier.issue(claims(subject, AUDIENCE, 60));
        token(federated(agent.clientId(), replayed));
        rejected(federated(agent.clientId(), replayed), "replay");
        rejected(federated(other.clientId(), SyntheticWorkloadAssertionVerifier.issue(claims(subject, AUDIENCE, 60))),
                "another workload's client");
        rejected(federated(agent.clientId(), SyntheticWorkloadAssertionVerifier.issue(claims(subject,
                "https://elsewhere.invalid/token", 60))), "wrong audience");
        rejected(federated(agent.clientId(), SyntheticWorkloadAssertionVerifier.issue(claims(subject, AUDIENCE, -10))),
                "expired");
        rejected(federated(agent.clientId(), SyntheticWorkloadAssertionVerifier.issue(claims(subject, AUDIENCE, 3600))),
                "lifetime too long");
        rejected(federated(agent.clientId(), SyntheticWorkloadAssertionVerifier.issue(claims("workload/unbound", AUDIENCE,
                60))), "unbound identity");
        String forged = SyntheticWorkloadAssertionVerifier.issue(claims(subject, AUDIENCE, 60));
        rejected(federated(agent.clientId(), forged.substring(0, forged.length() - 3) + "abc"), "bad signature");

        // The federated workload cannot redeem another workload's authority.
        String ledgerAud = "ledger:" + t.id + ":" + t.s;
        app(t, "ledger", ledgerAud);
        route(t, other.workloadId(), "RESOURCE", null, ledgerAud, List.of(READ));
        String owner = principal(t.id, t.s + "-owner", null);
        entitle(t, other.appId(), owner, List.of(READ));
        String grant = body(send(post("/api/me/standing-grants"), login(owner), Map.of("agentWorkloadId",
                other.workloadId(), "audience", ledgerAud, "scopes", List.of(READ), "purpose", "p",
                "expiresAt", Instant.now().plusSeconds(1800).toString())), 201).path("id").asText();
        MvcResult stolen = mvc.perform(federatedRequest(agent.clientId(), SyntheticWorkloadAssertionVerifier.issue(
                claims(subject, AUDIENCE, 60))).param("grant_type", "urn:openwolf:params:oauth:grant-type:standing-grant")
                .param("standing_grant", grant).param("scope", READ)).andReturn();
        assertThat(stolen.getResponse().getStatus()).isIn(400, 401);
        assertThat(stolen.getResponse().getContentAsString()).doesNotContain("access_token");

        // Workload suspension and binding revocation stop federation immediately.
        body(send(post(base(t) + "/ciam/agent-workloads/" + agent.workloadId() + "/suspend"), t.admin, null), 200);
        rejected(federated(agent.clientId(), SyntheticWorkloadAssertionVerifier.issue(claims(subject, AUDIENCE, 60))),
                "suspended workload");
        body(send(post(base(t) + "/ciam/agent-workloads/" + agent.workloadId() + "/reactivate"), t.admin, null), 200);
        token(federated(agent.clientId(), SyntheticWorkloadAssertionVerifier.issue(claims(subject, AUDIENCE, 60))));
        body(send(post(base(t) + "/ciam/agent-workloads/" + agent.workloadId() + "/federation-bindings/" + binding
                + "/revoke"), t.admin, null), 200);
        rejected(federated(agent.clientId(), SyntheticWorkloadAssertionVerifier.issue(claims(subject, AUDIENCE, 60))),
                "revoked binding");
    }

    private static Map<String, Object> claims(String subject, String audience, long lifetimeSeconds) {
        long now = Instant.now().getEpochSecond();
        return Map.of("iss", ISSUER, "sub", subject, "aud", audience, "iat", now,
                "exp", now + lifetimeSeconds, "jti", UUID.randomUUID().toString());
    }

    private MockHttpServletRequestBuilder federatedRequest(String clientId, String assertion) {
        return post("/oauth/token").contentType(MediaType.APPLICATION_FORM_URLENCODED).param("client_id", clientId)
                .param("client_assertion_type", WorkloadFederationClientAuthentication.ASSERTION_TYPE)
                .param("client_assertion_profile", SyntheticWorkloadAssertionVerifier.PROFILE)
                .param("client_assertion", assertion);
    }

    private MvcResult federated(String clientId, String assertion) throws Exception {
        return mvc.perform(federatedRequest(clientId, assertion).param("grant_type", "client_credentials")
                .param("scope", READ)).andReturn();
    }

    private void rejected(MvcResult r, String why) throws Exception {
        assertThat(r.getResponse().getStatus()).as(why).isEqualTo(401);
        assertThat(r.getResponse().getContentAsString()).as(why).contains("invalid_client").doesNotContain("access_token");
    }
}
