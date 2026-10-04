package com.openwolf.iam.authority;

import com.fasterxml.jackson.databind.JsonNode;
import com.openwolf.iam.IamApplication;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.web.servlet.MvcResult;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;

/**
 * Phase 3 measurements (one machine, in-process MockMvc, disposable PostgreSQL/Redis containers): token and header
 * sizes for the new token types, and wall-clock latency of the new operations including confidential-client
 * authentication (BCrypt cost 12). These are observations of this fixture, not performance claims.
 */
@SpringBootTest(classes = IamApplication.class, webEnvironment = SpringBootTest.WebEnvironment.MOCK)
@AutoConfigureMockMvc
class AuthorityMeasurementIT extends AuthorityITSupport {
    static final int RUNS = 30;

    @Test
    void measureTokenSizesAndOperationLatency() throws Exception {
        Tenant t = tenant("p3f-m");
        Svc agent = workload(t, "agent", List.of(READ, PAY));
        String ledgerAud = "ledger:" + t.id + ":" + t.s;
        String ledgerApp = app(t, "ledger", ledgerAud);
        Svc ledger = confidential(t, ledgerApp, ledgerAud, t.s + "-ledger", List.of(READ));
        route(t, agent.workloadId(), "RESOURCE", null, ledgerAud, List.of(READ, PAY));
        String owner = principal(t.id, t.s + "-owner", null);
        entitle(t, agent.appId(), owner, Map.of(READ, "allow", PAY, "cosign"));
        String approver = principal(t.id, t.s + "-approver", "action_approver");
        String ownerToken = login(owner);
        String grant = body(send(post("/api/me/standing-grants"), ownerToken, Map.of("agentWorkloadId", agent.workloadId(),
                "audience", ledgerAud, "scopes", List.of(READ), "purpose", "Nightly",
                "expiresAt", Instant.now().plusSeconds(1800).toString())), 201).path("id").asText();
        JsonNode first = tokenResponse(tokenRequest(agent, Map.of("grant_type",
                "urn:openwolf:params:oauth:grant-type:standing-grant", "standing_grant", grant, "scope", READ)));
        String handle = first.path("renewal_handle").asText();
        String standingToken = first.path("access_token").asText();
        String workloadToken = clientCredentials(agent, READ);

        List<Long> renew = new ArrayList<>();
        List<Long> introspectStanding = new ArrayList<>();
        List<Long> resume = new ArrayList<>();
        String task = body(send(post("/api/v1/workload/tasks"), workloadToken, Map.of("authorityType", "STANDING_GRANT",
                "authorityId", grant, "taskRef", "measure")), 201).path("id").asText();
        for (int i = 0; i < RUNS; i++) {
            long start = System.nanoTime();
            JsonNode renewed = tokenResponse(tokenRequest(agent, Map.of("grant_type",
                    "urn:openwolf:params:oauth:grant-type:standing-grant", "standing_grant", grant,
                    "renewal_handle", handle, "scope", READ)));
            renew.add(System.nanoTime() - start);
            handle = renewed.path("renewal_handle").asText();
            start = System.nanoTime();
            assertThat(introspect(ledger, renewed.path("access_token").asText()).path("active").asBoolean()).isTrue();
            introspectStanding.add(System.nanoTime() - start);
            start = System.nanoTime();
            body(send(post("/api/v1/workload/tasks/" + task + "/resume"), workloadToken, null), 200);
            resume.add(System.nanoTime() - start);
        }

        List<Long> redeem = new ArrayList<>();
        String approvedToken = null;
        for (int i = 0; i < 10; i++) {
            JsonNode requested = body(send(post("/api/v1/action-approvals"), login(owner), Map.of("agentWorkloadId",
                    agent.workloadId(), "receiverAudience", ledgerAud, "scopes", List.of(PAY), "actionType",
                    "payment.execute", "action", json.readTree("{\"invoice\":\"INV-" + i + "\",\"payee\":\"ACME\","
                            + "\"amount\":{\"currency\":\"GBP\",\"minor\":100}}"), "deadlineSeconds", 900,
                    "maxAuthAgeSeconds", 60)), 201);
            String id = requested.path("id").asText();
            String digest = requested.path("actionDigest").asText();
            body(send(post("/api/v1/action-approvals/" + id + "/approve"), login(approver), Map.of("actionDigest", digest)), 200);
            body(send(post("/api/v1/action-approvals/" + id + "/confirm"), login(owner), Map.of("actionDigest", digest)), 200);
            long start = System.nanoTime();
            MvcResult r = tokenRequest(agent, Map.of("grant_type", "urn:openwolf:params:oauth:grant-type:approved-action",
                    "approval_id", id, "action_digest", digest, "scope", PAY));
            redeem.add(System.nanoTime() - start);
            approvedToken = token(r);
        }

        Map<String, Object> out = new LinkedHashMap<>();
        out.put("fixture", "single machine, in-process MockMvc, Testcontainers PostgreSQL 16 + Redis 7; includes BCrypt-12 "
                + "client authentication; not a performance claim");
        out.put("axiom_admin_token_bytes", ownerToken.length());
        out.put("workload_client_credentials_token_bytes", workloadToken.length());
        out.put("standing_grant_token_bytes", standingToken.length());
        out.put("approved_action_token_bytes", approvedToken.length());
        out.put("renewal_handle_bytes", handle.length());
        String cookies = "SESSION=" + "s".repeat(48) + "; XSRF-TOKEN=" + "x".repeat(36) + "; _ga=GA1.1." + "1".repeat(20);
        int headers = ("Authorization: Bearer " + approvedToken).length() + ("Cookie: " + cookies).length()
                + ("traceparent: 00-" + "a".repeat(32) + "-" + "b".repeat(16) + "-01").length()
                + ("tracestate: vendor=" + "t".repeat(40)).length()
                + "Forwarded: for=10.1.2.3;proto=https;host=gateway.example.internal".length()
                + "X-Forwarded-For: 10.1.2.3, 10.4.5.6".length();
        out.put("representative_headers_with_approved_action_token_bytes", headers);
        out.put("standing_renewal_ms", stats(renew));
        out.put("standing_token_introspection_ms", stats(introspectStanding));
        out.put("task_resume_ms", stats(resume));
        out.put("approved_action_redemption_ms", stats(redeem));
        Files.writeString(Path.of("target", "phase3-measurements.json"),
                json.writerWithDefaultPrettyPrinter().writeValueAsString(out), StandardCharsets.UTF_8);
        System.out.println("PHASE3_MEASUREMENTS " + json.writeValueAsString(out));
    }

    private static Map<String, Object> stats(List<Long> nanos) {
        List<Long> sorted = new ArrayList<>(nanos);
        sorted.sort(Long::compare);
        Map<String, Object> s = new LinkedHashMap<>();
        s.put("samples", sorted.size());
        s.put("p50", round(sorted.get(sorted.size() / 2)));
        s.put("p95", round(sorted.get((int) Math.ceil(sorted.size() * 0.95) - 1)));
        s.put("max", round(sorted.getLast()));
        return s;
    }

    private static double round(long nanos) { return Math.round(nanos / 10_000.0) / 100.0; }
}
