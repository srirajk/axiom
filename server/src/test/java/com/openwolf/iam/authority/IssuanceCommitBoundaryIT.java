package com.openwolf.iam.authority;

import com.fasterxml.jackson.databind.JsonNode;
import com.openwolf.iam.IamApplication;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.test.web.servlet.MvcResult;

import java.time.Instant;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;

/**
 * The PostgreSQL commit-failure boundary of Phase 3 issuance (ordering, not cross-store atomicity). A deferred
 * constraint trigger, created only in this disposable test database, makes the PostgreSQL commit fail after the token
 * was signed and its Redis record written. Evidence: no token is returned; PostgreSQL state is unchanged (approval still
 * CONFIRMED, handle not rotated); an orphan Redis record does exist and expires with the token plus the store's grace;
 * the orphan's Axiom session row was rolled back with the transaction, so introspection never accepts the orphan —
 * including after the approval is later redeemed successfully with otherwise identical claims.
 */
@SpringBootTest(classes = IamApplication.class, webEnvironment = SpringBootTest.WebEnvironment.MOCK)
@AutoConfigureMockMvc
class IssuanceCommitBoundaryIT extends AuthorityITSupport {
    static final String APPROVED = "urn:openwolf:params:oauth:grant-type:approved-action";
    static final String STANDING = "urn:openwolf:params:oauth:grant-type:standing-grant";

    @Autowired StringRedisTemplate redis;
    @Autowired OAuth2AuthorizationService authorizations;

    @BeforeEach
    void installCommitFailureInjection() {
        jdbc.execute("CREATE TABLE IF NOT EXISTS p3_test_commit_failures (row_id UUID PRIMARY KEY)");
        jdbc.execute("CREATE OR REPLACE FUNCTION p3_test_fail_commit() RETURNS trigger AS $$ BEGIN "
                + "IF EXISTS (SELECT 1 FROM p3_test_commit_failures WHERE row_id = NEW.id) THEN "
                + "RAISE EXCEPTION 'injected commit failure'; END IF; RETURN NEW; END $$ LANGUAGE plpgsql");
        for (String table : List.of("action_approvals", "standing_grants")) {
            jdbc.execute("DROP TRIGGER IF EXISTS p3_test_fail_commit ON " + table);
            jdbc.execute("CREATE CONSTRAINT TRIGGER p3_test_fail_commit AFTER UPDATE ON " + table
                    + " DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION p3_test_fail_commit()");
        }
    }

    @AfterEach
    void removeCommitFailureInjection() {
        for (String table : List.of("action_approvals", "standing_grants")) {
            jdbc.execute("DROP TRIGGER IF EXISTS p3_test_fail_commit ON " + table);
        }
        jdbc.execute("DROP FUNCTION IF EXISTS p3_test_fail_commit()");
        jdbc.execute("DROP TABLE IF EXISTS p3_test_commit_failures");
    }

    @Test
    void approvedActionCommitFailureLeavesTheApprovalUnconsumedAndItsOrphanTokenUnusable() throws Exception {
        Tenant t = tenant("p3r-b");
        Svc agent = workload(t, "agent", List.of(PAY));
        String receiverAud = "payments:" + t.id + ":" + t.s;
        Svc receiver = confidential(t, app(t, "payments", receiverAud), receiverAud, t.s + "-payments", List.of(PAY));
        route(t, agent.workloadId(), "RESOURCE", null, receiverAud, List.of(PAY));
        String initiator = principal(t.id, t.s + "-initiator", null);
        entitle(t, agent.appId(), initiator, Map.of(PAY, "cosign"));
        String approver = principal(t.id, t.s + "-approver", "action_approver");
        JsonNode requested = body(send(post("/api/v1/action-approvals"), login(initiator), Map.of("agentWorkloadId",
                agent.workloadId(), "receiverAudience", receiverAud, "scopes", List.of(PAY), "actionType", "payment.execute",
                "action", json.readTree("{\"invoice\":\"INV-1\",\"amount\":{\"currency\":\"GBP\",\"minor\":100}}"),
                "deadlineSeconds", 900, "maxAuthAgeSeconds", 60)), 201);
        String id = requested.path("id").asText();
        String digest = requested.path("actionDigest").asText();
        body(send(post("/api/v1/action-approvals/" + id + "/approve"), login(approver), Map.of("actionDigest", digest)), 200);
        body(send(post("/api/v1/action-approvals/" + id + "/confirm"), login(initiator), Map.of("actionDigest", digest)), 200);

        Set<String> before = records(t);
        jdbc.update("INSERT INTO p3_test_commit_failures (row_id) VALUES (?::uuid)", id);
        MvcResult failed = tokenRequest(agent, Map.of("grant_type", APPROVED, "approval_id", id, "action_digest", digest,
                "scope", PAY));
        assertThat(failed.getResponse().getStatus()).isNotEqualTo(200);
        assertThat(failed.getResponse().getContentAsString()).doesNotContain("access_token");
        assertThat(jdbc.queryForObject("SELECT status FROM action_approvals WHERE id = ?::uuid", String.class, id))
                .isEqualTo("CONFIRMED");
        String orphan = orphanToken(t, before);
        assertNoSession(orphan);
        assertThat(introspect(receiver, orphan).path("active").asBoolean()).as("orphan before redemption").isFalse();

        jdbc.update("DELETE FROM p3_test_commit_failures");
        String issued = token(tokenRequest(agent, Map.of("grant_type", APPROVED, "approval_id", id, "action_digest", digest,
                "scope", PAY)));
        assertThat(introspect(receiver, issued).path("active").asBoolean()).isTrue();
        assertThat(introspect(receiver, orphan).path("active").asBoolean())
                .as("orphan after the approval was redeemed").isFalse();
        assertThat(claims(orphan).get("ap_ver")).as("the orphan's claims otherwise match").isEqualTo(claims(issued).get("ap_ver"));
        denied(tokenRequest(agent, Map.of("grant_type", APPROVED, "approval_id", id, "action_digest", digest,
                "scope", PAY)), "invalid_grant");
    }

    @Test
    void standingRenewalCommitFailureKeepsTheHandleAndLeavesAnExpiringOrphanRecord() throws Exception {
        Tenant t = tenant("p3r-b");
        Svc agent = workload(t, "agent", List.of(READ));
        String ledgerAud = "ledger:" + t.id + ":" + t.s;
        app(t, "ledger", ledgerAud);
        route(t, agent.workloadId(), "RESOURCE", null, ledgerAud, List.of(READ));
        String owner = principal(t.id, t.s + "-owner", null);
        entitle(t, agent.appId(), owner, List.of(READ));
        String grant = body(send(post("/api/me/standing-grants"), login(owner), Map.of("agentWorkloadId", agent.workloadId(),
                "audience", ledgerAud, "scopes", List.of(READ), "purpose", "Nightly",
                "expiresAt", Instant.now().plusSeconds(1800).toString())), 201).path("id").asText();
        String handle = tokenResponse(tokenRequest(agent, Map.of("grant_type", STANDING, "standing_grant", grant,
                "scope", READ))).path("renewal_handle").asText();

        Set<String> before = records(t);
        jdbc.update("INSERT INTO p3_test_commit_failures (row_id) VALUES (?::uuid)", grant);
        MvcResult failed = tokenRequest(agent, Map.of("grant_type", STANDING, "standing_grant", grant,
                "renewal_handle", handle, "scope", READ));
        assertThat(failed.getResponse().getStatus()).isNotEqualTo(200);
        assertThat(failed.getResponse().getContentAsString()).doesNotContain("access_token").doesNotContain("renewal_handle");
        assertThat(jdbc.queryForObject("SELECT handle_generation FROM standing_grants WHERE id = ?::uuid", Long.class, grant))
                .as("rotation rolled back").isEqualTo(1L);
        String orphanKey = orphanKey(t, before);
        String orphan = authorizations.findById(orphanKey.substring(orphanKey.lastIndexOf(':') + 1))
                .getAccessToken().getToken().getTokenValue();
        assertNoSession(orphan);
        assertThat(introspect(agent, orphan).path("active").asBoolean()).as("standing orphan").isFalse();
        Long ttl = redis.getExpire(orphanKey);
        // The store keeps records until token expiry plus its fixed 60 s grace: <= 5 min token TTL + 60 s.
        assertThat(ttl).as("orphan record expires with its token").isNotNull().isBetween(1L, 360L);

        jdbc.update("DELETE FROM p3_test_commit_failures");
        assertThat(tokenResponse(tokenRequest(agent, Map.of("grant_type", STANDING, "standing_grant", grant,
                "renewal_handle", handle, "scope", READ))).path("renewal_handle").asText())
                .as("the presented handle was not consumed").isNotEqualTo(handle);
    }

    // =================================================================================================================

    /** The token's Axiom session was written in the failed transaction and therefore does not exist. */
    private void assertNoSession(String token) throws Exception {
        Object sid = claims(token).get("sid");
        assertThat(sid).isNotNull();
        assertThat(jdbc.queryForObject("SELECT count(*) FROM iam_sessions WHERE id = ?::uuid", Integer.class, sid))
                .isZero();
    }

    private Set<String> records(Tenant t) {
        Set<String> keys = redis.keys("iam:t:" + t.id + ":oauth2:authorization:*");
        return keys == null ? Set.of() : new HashSet<>(keys);
    }

    private String orphanKey(Tenant t, Set<String> before) {
        Set<String> after = records(t);
        after.removeAll(before);
        assertThat(after).as("the failed attempt left exactly one Redis record").hasSize(1);
        return after.iterator().next();
    }

    private String orphanToken(Tenant t, Set<String> before) {
        String key = orphanKey(t, before);
        OAuth2Authorization orphan = authorizations.findById(key.substring(key.lastIndexOf(':') + 1));
        assertThat(orphan).isNotNull();
        return orphan.getAccessToken().getToken().getTokenValue();
    }

}
