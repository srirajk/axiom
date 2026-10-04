package com.openwolf.iam.invocation;

import com.openwolf.iam.IamApplication;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.test.web.servlet.MvcResult;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;

/** Gate D — Phase 2.9 durable revocation and lifecycle wiring, 2.11 retries/fan-out under revocation races. */
@SpringBootTest(classes = IamApplication.class, webEnvironment = SpringBootTest.WebEnvironment.MOCK)
@AutoConfigureMockMvc
@Import(SyntheticInvocationAuthorizationVerifier.Config.class)
class InvocationContextRevocationIT extends InvocationContextITSupport {

    @Test
    void sessionRevocationEndsEveryRunOfThatSessionOnly() throws Exception {
        World w = world("icr-a");
        String user = member(w, "claims");
        Entry first = enter(w, "claims", user);
        Established runA = establish(w, first, Map.of());
        Established runB = establish(w, first, Map.of());
        Entry otherSession = enter(w, "claims", user);
        Established runC = establish(w, otherSession, Map.of());
        // Scoped: revoking run A leaves run B (same session) and run C running.
        body(revokeContext(w, runA.contextId()), 200);
        denied(exchange(w.agent, runA.token(), w.gatewayAud, SCOPE, Map.of()), "invalid_grant");
        token(exchange(w.agent, runB.token(), w.gatewayAud, SCOPE, Map.of()));
        // Logout / administrative session revoke ends every run of that session, not of the user's other session.
        long revision = jdbc.queryForObject("SELECT revision FROM iam_sessions WHERE id = ?::uuid", Long.class, first.rootSession());
        body(send(post(base(w) + "/sessions/" + first.rootSession() + "/revoke"), w.admin, Map.of("expectedRevision", revision)), 200);
        assertThat(row(runB.contextId())).containsEntry("status", "REVOKED").containsEntry("revocation_reason", "session revoked");
        denied(exchange(w.agent, runB.token(), w.gatewayAud, SCOPE, Map.of()), "invalid_grant");
        assertThat(row(runC.contextId())).containsEntry("status", "ACTIVE");
        token(exchange(w.agent, runC.token(), w.gatewayAud, SCOPE, Map.of()));
    }

    @Test
    void identityDisableRevokesButAssignmentRemovalDoesNot() throws Exception {
        World w = world("icr-a");
        String disabled = member(w, "claims");
        String reassigned = member(w, "wealth");
        Established d = establish(w, enter(w, "claims", disabled), Map.of());
        Established r = establish(w, enter(w, "wealth", reassigned), Map.of());
        body(send(put("/users/" + disabled), w.admin, Map.of("isActive", false)), 200);
        assertThat(row(d.contextId())).containsEntry("status", "REVOKED").containsEntry("revocation_reason", "identity disabled");
        denied(exchange(w.agent, d.token(), w.gatewayAud, SCOPE, Map.of()), "invalid_grant");
        // Removing the role assignment is not revocation: the context stays active and is bounded by its deadline.
        String membership = jdbc.queryForObject("SELECT id::text FROM tenant_application_memberships WHERE principal_id = ?",
                String.class, reassigned);
        body(send(delete(base(w) + "/applications/" + w.uc("wealth").appId + "/access/memberships/" + membership
                + "/roles/" + w.uc("wealth").role), w.admin, null), 200);
        assertThat(row(r.contextId())).containsEntry("status", "ACTIVE");
        token(exchange(w.agent, r.token(), w.gatewayAud, SCOPE, Map.of()));
    }

    @Test
    void noContinuationSucceedsAfterARevokeCommits() throws Exception {
        World w = world("icr-a");
        Established est = establish(w, enter(w, "claims", member(w, "claims")), Map.of());
        ExecutorService pool = Executors.newFixedThreadPool(6);
        CountDownLatch start = new CountDownLatch(1);
        try {
            List<Future<long[]>> continuations = new ArrayList<>();
            for (int i = 0; i < 6; i++) {
                continuations.add(pool.submit(() -> {
                    start.await();
                    List<long[]> outcomes = new ArrayList<>();
                    for (int k = 0; k < 10; k++) {
                        long begin = System.nanoTime();
                        MvcResult r = exchange(w.agent, est.token(), w.gatewayAud, SCOPE, Map.of());
                        outcomes.add(new long[]{begin, r.getResponse().getStatus()});
                    }
                    long lastSuccessBegin = outcomes.stream().filter(o -> o[1] == 200).mapToLong(o -> o[0]).max().orElse(0);
                    return new long[]{lastSuccessBegin};
                }));
            }
            start.countDown();
            Thread.sleep(150);
            body(revokeContext(w, est.contextId()), 200);
            long revokedAt = System.nanoTime();
            for (Future<long[]> f : continuations) {
                assertThat(f.get(60, TimeUnit.SECONDS)[0]).as("a success must have started before the revoke returned")
                        .isLessThan(revokedAt);
            }
        } finally {
            pool.shutdownNow();
        }
        denied(exchange(w.agent, est.token(), w.gatewayAud, SCOPE, Map.of()), "invalid_grant");
        assertThat(row(est.contextId())).containsEntry("status", "REVOKED").containsEntry("version", 2L);
    }

    @Test
    void branchesCreatedWhileTheRootIsRevokedNeverCarryAuthority() throws Exception {
        World w = world("icr-a");
        Established est = establish(w, enter(w, "claims", member(w, "claims")), Map.of());
        ExecutorService pool = Executors.newFixedThreadPool(MAX_BRANCHES + 1);
        CountDownLatch start = new CountDownLatch(1);
        List<Future<MvcResult>> branches = new ArrayList<>();
        try {
            for (int i = 0; i < MAX_BRANCHES; i++) {
                int k = i;
                branches.add(pool.submit(() -> {
                    start.await();
                    return exchange(w.agent, est.token(), w.gatewayAud, SCOPE, Map.of("invocation_branch", "race" + k));
                }));
            }
            Future<MvcResult> revoke = pool.submit(() -> {
                start.await();
                return revokeContext(w, est.contextId());
            });
            start.countDown();
            body(revoke.get(60, TimeUnit.SECONDS), 200);
            for (Future<MvcResult> f : branches) {
                MvcResult r = f.get(60, TimeUnit.SECONDS);
                if (r.getResponse().getStatus() == 200) {
                    // Issued in the race window: unusable now, whatever its row's own status.
                    denied(exchange(w.broker, token(r), w.toolAud, SCOPE, Map.of()), "invalid_grant");
                }
            }
        } finally {
            pool.shutdownNow();
        }
        denied(exchange(w.agent, est.token(), w.gatewayAud, SCOPE, Map.of("invocation_branch", "late")), "invalid_grant");
    }

    @Test
    void issuanceRetryAfterRevocationNeverRevivesTheContext() throws Exception {
        World w = world("icr-a");
        Entry e = enter(w, "claims", member(w, "claims"));
        String evidence = evidence(w, e, w.agentAud, Set.of(SCOPE), Instant.now().plusSeconds(600));
        Map<String, String> params = Map.of("invocation_authorization", evidence, "invocation_idempotency_key", "retry-1");
        Established est = new Established(e, token(exchange(w.broker, e.p3(), w.agentAud, SCOPE, params)), null, null);
        String ctx = (String) claims(est.token()).get("ctx");
        body(revokeContext(w, ctx), 200);
        List<MvcResult> retries = InvocationContextEstablishmentIT.parallel(6,
                i -> exchange(w.broker, e.p3(), w.agentAud, SCOPE, params));
        for (MvcResult r : retries) denied(r, "invalid_grant");
        assertThat(jdbc.queryForObject("SELECT count(*) FROM invocation_contexts WHERE idempotency_key = 'retry-1' "
                + "AND tenant_id = ?", Integer.class, w.tenant)).isEqualTo(1);
        assertThat(row(ctx)).containsEntry("status", "REVOKED").containsEntry("version", 2L);
    }
}
