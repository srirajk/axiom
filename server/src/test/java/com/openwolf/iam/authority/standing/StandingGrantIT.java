package com.openwolf.iam.authority.standing;

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
 * Phase 3.3 standing offline authority: explicit owner approval with fresh authentication; redemption only by the
 * bound workload with a rotating, single-use renewal handle; no access token is ever renewal material; withdrawal,
 * expiry, owner disable, entitlement loss and handle reuse stop renewal and existing tokens; state survives restart;
 * PostgreSQL and Redis outages fail closed without consuming the handle.
 */
@SpringBootTest(classes = IamApplication.class, webEnvironment = SpringBootTest.WebEnvironment.MOCK)
@AutoConfigureMockMvc
class StandingGrantIT extends AuthorityITSupport {
    static final String GRANT = "urn:openwolf:params:oauth:grant-type:standing-grant";

    record Fixture(Tenant t, Svc agent, Svc other, String ledgerAud, String owner, String membership) {}

    @Test
    void ownerApprovesTheWorkloadRedeemsAndRenewsWithRotatingHandles() throws Exception {
        Fixture f = fixture();
        JsonNode grant = approve(f, f.owner, List.of(READ), Instant.now().plusSeconds(1800), 201);
        assertThat(grant.path("status").asText()).isEqualTo("APPROVED");
        String id = grant.path("id").asText();

        JsonNode first = tokenResponse(redeem(f.agent, id, null, READ, null));
        String h1 = first.path("renewal_handle").asText();
        Map<String, Object> claims = claims(first.path("access_token").asText());
        assertThat(claims).containsEntry("sub", f.owner).containsEntry("aud", f.ledgerAud)
                .containsEntry("authority_profile", "standing_grant").containsEntry("standing_grant_id", id)
                .containsEntry("sg_ver", 1).containsEntry("token_use", "delegated_access");
        assertThat(((Map<?, ?>) claims.get("act")).get("client_id")).isEqualTo(f.agent.clientId());
        assertThat(introspect(f.agent, first.path("access_token").asText()).path("active").asBoolean()).isTrue();

        // A second claim without a handle, another workload, a wider scope or a wrong handle all fail.
        denied(redeem(f.agent, id, null, READ, null), "invalid_grant");
        assertThat(redeem(f.other, id, h1, READ, null).getResponse().getStatus()).isIn(400, 401);
        denied(redeem(f.agent, id, h1, READ + " " + WRITE, null), "invalid_scope");
        denied(redeem(f.agent, id, "x".repeat(43), READ, null), "invalid_grant");

        JsonNode second = tokenResponse(redeem(f.agent, id, h1, READ, null));
        String h2 = second.path("renewal_handle").asText();
        assertThat(h2).isNotEqualTo(h1);
        // The superseded handle comes back: treated as theft — the grant is withdrawn and its tokens stop.
        denied(redeem(f.agent, id, h1, READ, null), "invalid_grant");
        assertThat(grantRow(id)).containsEntry("status", "REVOKED").containsEntry("version", 2L);
        assertThat(introspect(f.agent, second.path("access_token").asText()).path("active").asBoolean()).isFalse();
        denied(redeem(f.agent, id, h2, READ, null), "invalid_grant");

        String audit = auditText(f.t.id);
        assertThat(audit).contains("handle_generation").doesNotContain(h1).doesNotContain(h2);
        assertThat(jdbc.queryForObject("SELECT count(*) FROM audit_log WHERE action = 'STANDING_GRANT_REVOKED' "
                + "AND resource_id = ?", Integer.class, id)).isEqualTo(1);
    }

    @Test
    void anAccessTokenIsNeverRenewalMaterialAndStandingTokensAreNotTransitive() throws Exception {
        Fixture f = fixture();
        String id = approve(f, f.owner, List.of(READ), Instant.now().plusSeconds(4), 201).path("id").asText();
        JsonNode issued = tokenResponse(redeem(f.agent, id, null, READ, null));
        String access = issued.path("access_token").asText();
        assertThat(claims(access).get("exp")).as("token never outlives the grant")
                .satisfies(exp -> assertThat(((Number) exp).longValue()).isLessThanOrEqualTo(Instant.now().getEpochSecond() + 5));
        Map<String, String> withToken = new HashMap<>(Map.of("grant_type", GRANT, "standing_grant", id, "scope", READ,
                "subject_token", access));
        denied(tokenRequest(f.agent, withToken), "invalid_request");
        assertThat(exchange(f.agent, access, f.agent.audience(), READ, Map.of()).getResponse().getStatus())
                .as("a standing token cannot be exchanged onward").isIn(400, 401);

        Thread.sleep(5000);
        assertThat(introspect(f.agent, access).path("active").asBoolean()).as("expired token").isFalse();
        denied(redeem(f.agent, id, issued.path("renewal_handle").asText(), READ, null), "invalid_grant");
    }

    @Test
    void approvalRequiresFreshOwnerAuthenticationCurrentEntitlementAndARoute() throws Exception {
        Fixture f = fixture();
        String token = login(f.owner);
        assertThat(approveWith(f, token, List.of(WRITE), Instant.now().plusSeconds(3600)).getResponse().getStatus())
                .as("owner not entitled to WRITE").isEqualTo(403);
        assertThat(approveWith(f, token, List.of(PAY), Instant.now().plusSeconds(3600)).getResponse().getStatus())
                .as("co-signed permission cannot be exercised offline").isEqualTo(403);
        assertThat(approveWith(f, token, List.of(READ), Instant.now().plusSeconds(40 * 86400L)).getResponse().getStatus())
                .as("beyond maximum lifetime").isEqualTo(400);
        assertThat(send(post("/api/me/standing-grants"), token, Map.of("agentWorkloadId", f.agent.workloadId(),
                "audience", "nowhere:" + f.t.s, "scopes", List.of(READ), "purpose", "p",
                "expiresAt", Instant.now().plusSeconds(3600).toString())).getResponse().getStatus())
                .as("no route to that audience").isEqualTo(400);
        assertThat(send(post("/api/me/standing-grants"), clientCredentials(f.agent, READ), Map.of("agentWorkloadId",
                f.agent.workloadId(), "audience", f.ledgerAud, "scopes", List.of(READ), "purpose", "p",
                "expiresAt", Instant.now().plusSeconds(3600).toString())).getResponse().getStatus())
                .as("a workload cannot approve for anyone").isEqualTo(401);
        Thread.sleep(6000);
        assertThat(approveWith(f, token, List.of(READ), Instant.now().plusSeconds(3600)).getResponse().getStatus())
                .as("authentication no longer fresh").isEqualTo(403);
        assertThat(jdbc.queryForObject("SELECT count(*) FROM standing_grants WHERE owner_principal_id = ?",
                Integer.class, f.owner)).isZero();
    }

    @Test
    void ownerDisableEntitlementRemovalRouteRevocationAndWithdrawalStopOfflineWork() throws Exception {
        Fixture f = fixture();
        String id = approve(f, f.owner, List.of(READ), Instant.now().plusSeconds(1800), 201).path("id").asText();
        JsonNode issued = tokenResponse(redeem(f.agent, id, null, READ, null));
        String handle = issued.path("renewal_handle").asText();
        String access = issued.path("access_token").asText();

        jdbc.update("UPDATE principals SET is_active = FALSE WHERE id = ?", f.owner);
        assertThat(introspect(f.agent, access).path("active").asBoolean()).isFalse();
        denied(redeem(f.agent, id, handle, READ, null), "invalid_grant");
        jdbc.update("UPDATE principals SET is_active = TRUE WHERE id = ?", f.owner);

        body(send(org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete(base(f.t) + "/applications/"
                + f.agent.appId() + "/access/memberships/" + f.membership), f.t.admin, null), 204);
        denied(redeem(f.agent, id, handle, READ, null), "invalid_grant");
        assertThat(grantRow(id)).containsEntry("handle_generation", 1L);

        // Withdrawal is permanent even if entitlement comes back.
        body(send(post(base(f.t) + "/applications/" + f.agent.appId() + "/access/memberships/" + f.membership
                + "/enable"), f.t.admin, null), 200);
        JsonNode renewed = tokenResponse(redeem(f.agent, id, handle, READ, null));
        body(send(post("/api/me/standing-grants/" + id + "/revoke"), login(f.owner), Map.of("reason", "no longer needed")), 200);
        assertThat(introspect(f.agent, renewed.path("access_token").asText()).path("active").asBoolean()).isFalse();
        denied(redeem(f.agent, id, renewed.path("renewal_handle").asText(), READ, null), "invalid_grant");

        // An administrator can withdraw but never approve on an owner's behalf.
        String second = approve(f, f.owner, List.of(READ), Instant.now().plusSeconds(1800), 201).path("id").asText();
        String h = tokenResponse(redeem(f.agent, second, null, READ, null)).path("renewal_handle").asText();
        body(send(post(base(f.t) + "/standing-grants/" + second + "/revoke"), f.t.admin, Map.of("reason", "admin")), 200);
        denied(redeem(f.agent, second, h, READ, null), "invalid_grant");
    }

    @Test
    void concurrentRenewalsIssueOneTokenAndAreTreatedAsReuse() throws Exception {
        Fixture f = fixture();
        String id = approve(f, f.owner, List.of(READ), Instant.now().plusSeconds(1800), 201).path("id").asText();
        String handle = tokenResponse(redeem(f.agent, id, null, READ, null)).path("renewal_handle").asText();
        List<MvcResult> results = parallel(6, i -> redeem(f.agent, id, handle, READ, null));
        long issued = results.stream().filter(r -> r.getResponse().getStatus() == 200).count();
        assertThat(issued).as("exactly one rotation").isEqualTo(1);
        for (MvcResult r : results) if (r.getResponse().getStatus() != 200) denied(r, "invalid_grant");
        assertThat(grantRow(id)).containsEntry("status", "REVOKED").containsEntry("handle_generation", 2L);
    }

    @Test
    void grantStateAndHandleSurviveARestart() throws Exception {
        Fixture f = fixture();
        String id = approve(f, f.owner, List.of(READ), Instant.now().plusSeconds(1800), 201).path("id").asText();
        String handle = tokenResponse(redeem(f.agent, id, null, READ, null)).path("renewal_handle").asText();
        try (ConfigurableApplicationContext restarted = new SpringApplicationBuilder(IamApplication.class)
                .web(WebApplicationType.SERVLET).run(commandLine())) {
            MockMvc fresh = MockMvcBuilders.webAppContextSetup((WebApplicationContext) restarted).apply(springSecurity()).build();
            MvcResult renewed = fresh.perform(post("/oauth/token").contentType(MediaType.APPLICATION_FORM_URLENCODED)
                    .header(HttpHeaders.AUTHORIZATION, basic(f.agent)).param("grant_type", GRANT)
                    .param("standing_grant", id).param("renewal_handle", handle).param("scope", READ)).andReturn();
            assertThat(renewed.getResponse().getStatus()).as(renewed.getResponse().getContentAsString()).isEqualTo(200);
        }
        assertThat(grantRow(id)).containsEntry("status", "ACTIVE").containsEntry("handle_generation", 2L);
    }

    @Test
    void dependencyOutagesFailClosedWithoutConsumingTheHandle() throws Exception {
        Fixture f = fixture();
        String id = approve(f, f.owner, List.of(READ), Instant.now().plusSeconds(1800), 201).path("id").asText();
        String handle = tokenResponse(redeem(f.agent, id, null, READ, null)).path("renewal_handle").asText();
        pause(REDIS);
        try {
            assertNoToken(() -> redeem(f.agent, id, handle, READ, null));
        } finally {
            unpause(REDIS);
        }
        Thread.sleep(500);
        assertThat(grantRow(id)).as("rolled back with the failed issuance").containsEntry("handle_generation", 1L);
        pause(POSTGRES);
        try {
            assertNoToken(() -> redeem(f.agent, id, handle, READ, null));
        } finally {
            unpause(POSTGRES);
        }
        awaitDatabase();
        JsonNode renewed = tokenResponse(redeem(f.agent, id, handle, READ, null));
        assertThat(renewed.path("renewal_handle").asText()).isNotEqualTo(handle);
        assertThat(grantRow(id)).containsEntry("status", "ACTIVE");
    }

    // =================================================================================================================

    private Fixture fixture() throws Exception {
        Tenant t = tenant("p3c-s");
        Svc agent = workload(t, "agent", List.of(READ, WRITE, PAY));
        Svc other = workload(t, "other", List.of(READ, WRITE, PAY));
        String ledgerAud = "ledger:" + t.id + ":" + t.s;
        app(t, "ledger", ledgerAud);
        route(t, agent.workloadId(), "RESOURCE", null, ledgerAud, List.of(READ, WRITE, PAY));
        route(t, other.workloadId(), "RESOURCE", null, ledgerAud, List.of(READ, WRITE, PAY));
        String owner = principal(t.id, t.s + "-owner-" + UUID.randomUUID().toString().substring(0, 4), null);
        String membership = entitle(t, agent.appId(), owner, Map.of(READ, "allow", PAY, "cosign"));
        return new Fixture(t, agent, other, ledgerAud, owner, membership);
    }

    private JsonNode approve(Fixture f, String owner, List<String> scopes, Instant expiresAt, int expected)
            throws Exception {
        return body(approveWith(f, login(owner), scopes, expiresAt), expected);
    }

    private MvcResult approveWith(Fixture f, String ownerToken, List<String> scopes, Instant expiresAt) throws Exception {
        return send(post("/api/me/standing-grants"), ownerToken, Map.of("agentWorkloadId", f.agent.workloadId(),
                "audience", f.ledgerAud, "scopes", scopes, "purpose", "Nightly reconciliation",
                "expiresAt", expiresAt.toString()));
    }

    MvcResult redeem(Svc client, String grantId, String handle, String scope, String taskId) throws Exception {
        Map<String, String> params = new HashMap<>(Map.of("grant_type", GRANT, "standing_grant", grantId, "scope", scope));
        if (handle != null) params.put("renewal_handle", handle);
        if (taskId != null) params.put("task_id", taskId);
        return tokenRequest(client, params);
    }

    private Map<String, Object> grantRow(String id) {
        return jdbc.queryForMap("SELECT status, version, handle_generation FROM standing_grants WHERE id = ?::uuid", id);
    }
}
