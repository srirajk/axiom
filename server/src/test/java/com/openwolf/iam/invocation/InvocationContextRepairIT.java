package com.openwolf.iam.invocation;

import com.openwolf.iam.IamApplication;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.test.web.servlet.MvcResult;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;

/**
 * Phase 2 repair: (1) resume and idempotent retry are bound to every immutable establishment fact; (2) branch creation
 * is serialized with every revocation path, proved with deterministic barriers (a probe holds one transaction at a
 * named point; the competing transaction is observed waiting on the row lock in {@code pg_stat_activity}); (3) the
 * ancestor chain is explicitly self-first.
 */
@SpringBootTest(classes = IamApplication.class, webEnvironment = SpringBootTest.WebEnvironment.MOCK)
@AutoConfigureMockMvc
@Import({SyntheticInvocationAuthorizationVerifier.Config.class, InvocationContextRepairIT.ProbeConfig.class})
class InvocationContextRepairIT extends InvocationContextITSupport {

    /** Holds the calling transaction at an armed point until released; a no-op otherwise. */
    static final class Barrier implements InvocationContextRaceProbe {
        private volatile String armed;
        private volatile CountDownLatch reached = new CountDownLatch(0);
        private volatile CountDownLatch release = new CountDownLatch(0);

        void arm(String point) {
            reached = new CountDownLatch(1);
            release = new CountDownLatch(1);
            armed = point;
        }

        @Override
        public void reached(String point, UUID contextId) {
            if (!point.equals(armed)) return;
            armed = null;
            reached.countDown();
            try {
                if (!release.await(60, TimeUnit.SECONDS)) throw new IllegalStateException("barrier never released");
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new IllegalStateException(e);
            }
        }

        void awaitReached() throws InterruptedException {
            assertThat(reached.await(60, TimeUnit.SECONDS)).as("barrier reached").isTrue();
        }

        void release() { release.countDown(); }

        void disarm() { armed = null; release.countDown(); }
    }

    @TestConfiguration
    static class ProbeConfig {
        @Bean
        Barrier invocationContextRaceProbe() { return new Barrier(); }
    }

    @Autowired Barrier barrier;
    @Autowired InvocationContextRepository repository;

    @AfterEach
    void releaseBarrier() { barrier.disarm(); }

    // =================================================================================================================
    // 1. Resume and idempotent retry bound to every immutable fact
    // =================================================================================================================

    @Test
    void resumeAndRetryRequireTheSameGatewayRoute() throws Exception {
        World w = world("icx-a");
        Entry e = enter(w, "claims", member(w, "claims"));
        Established est = establish(w, e, Map.of("invocation_idempotency_key", "route-1"));
        UseCase uc = e.useCase();
        // Replace R1 with another valid Gateway route for the same entry and Gateway.
        body(send(post(base(w) + "/agent-exchange/routes/" + uc.routeGateway + "/revoke"), w.admin, Map.of()), 200);
        String newRoute = route(w, uc.entry.workloadId(), "GATEWAY", null, w.gatewayAud, List.of(SCOPE, EXTRA));
        String p2 = token(exchange(uc.entry, e.p1(), uc.aud, SCOPE, Map.of()));
        String p3 = token(exchange(uc.entry, p2, w.gatewayAud, SCOPE, Map.of()));
        assertThat(claims(p3)).containsEntry("authority_id", newRoute).containsEntry("subject_sid", e.rootSession());
        denied(exchange(w.broker, p3, w.agentAud, SCOPE, Map.of("invocation_context", est.contextId())), "invalid_grant");
        denied(exchange(w.broker, p3, w.agentAud, SCOPE, Map.of("invocation_authorization",
                evidence(w, e, w.agentAud, Set.of(SCOPE), Instant.now().plusSeconds(600)),
                "invocation_idempotency_key", "route-1")), "invalid_grant");
    }

    @Test
    void resumeAndRetryRequireTheSameBroker() throws Exception {
        World w = world("icx-a");
        Entry e = enter(w, "claims", member(w, "claims"));
        Established est = establish(w, e, Map.of("invocation_idempotency_key", "broker-1"));
        // A second valid broker for a second Gateway, reachable from the same entry.
        String gw2 = "gw2:" + w.tenant + ":" + w.s;
        Svc broker2 = confidential(w, app(w, "gw2", gw2), w.s + "-broker2", List.of(SCOPE, EXTRA));
        body(send(post(base(w) + "/agent-exchange/brokers"), w.admin, Map.of("oauthClientId", broker2.clientId(),
                "gatewayAudience", gw2, "scopes", List.of(SCOPE, EXTRA))), 201);
        UseCase uc = e.useCase();
        route(w, uc.entry.workloadId(), "GATEWAY", null, gw2, List.of(SCOPE, EXTRA));
        String p2 = token(exchange(uc.entry, e.p1(), uc.aud, SCOPE, Map.of()));
        String p3 = token(exchange(uc.entry, p2, gw2, SCOPE, Map.of()));
        denied(exchange(broker2, p3, w.agentAud, SCOPE, Map.of("invocation_context", est.contextId())), "invalid_grant");
        denied(exchange(broker2, p3, w.agentAud, SCOPE, Map.of("invocation_authorization", "x.y",
                "invocation_idempotency_key", "broker-1")), "invalid_grant");
    }

    @Test
    void resumeAndRetryRequireTheSameDestination() throws Exception {
        World w = world("icx-a");
        Entry e = enter(w, "claims", member(w, "claims"));
        UseCase uc = e.useCase();
        // A second valid destination for the same entry.
        route(w, uc.entry.workloadId(), "AGENT", w.agent2.workloadId(), w.agent2Aud, List.of(SCOPE, EXTRA));
        Established est = establish(w, e, Map.of("invocation_idempotency_key", "dest-1"));
        assertThat(row(est.contextId())).containsEntry("destination_audience", w.agentAud);
        denied(exchange(w.broker, e.p3(), w.agent2Aud, SCOPE, Map.of("invocation_context", est.contextId())), "invalid_grant");
        denied(exchange(w.broker, e.p3(), w.agent2Aud, SCOPE, Map.of("invocation_authorization",
                evidence(w, e, w.agent2Aud, Set.of(SCOPE), Instant.now().plusSeconds(600)),
                "invocation_idempotency_key", "dest-1")), "invalid_grant");
        // Positive controls: same facts resume and retry.
        assertThat(claims(token(exchange(w.broker, e.p3(), w.agentAud, SCOPE, Map.of("invocation_context",
                est.contextId()))))).containsEntry("ctx", est.contextId());
        assertThat(claims(token(exchange(w.broker, e.p3(), w.agentAud, SCOPE, Map.of("invocation_authorization",
                evidence(w, e, w.agentAud, Set.of(SCOPE), Instant.now().plusSeconds(600)),
                "invocation_idempotency_key", "dest-1"))))).containsEntry("ctx", est.contextId());
    }

    @Autowired InvocationContextService contextService;

    /**
     * identity_kind is an immutable establishment fact. Axiom derives it from the subject, so a real token cannot change
     * it while subject, root session and every other fact still match; the service is therefore called directly with a
     * copy of a genuine Gateway-authorization token whose claims differ only in identity_kind.
     */
    @Test
    void resumeAndRetryRequireTheSameIdentityKind() throws Exception {
        World w = world("icx-a");
        Entry e = enter(w, "claims", member(w, "claims"));
        Established est = establish(w, e, Map.of("invocation_idempotency_key", "kind-1"));
        Map<String, Object> r = row(est.contextId());
        assertThat(r).containsEntry("identity_kind", "workforce");
        org.springframework.security.oauth2.jwt.Jwt original = jwt(e.p3(), null);
        org.springframework.security.oauth2.jwt.Jwt otherKind = jwt(e.p3(), "workload");
        InvocationContextService.Request resume = new InvocationContextService.Request(null, null, null, null, null,
                est.contextId());
        InvocationContextService.Request retry = new InvocationContextService.Request("unused.evidence", null, null,
                "kind-1", null, null);

        assertThatDenied(() -> contextService.establish(establishment(w, r, otherKind), resume));
        assertThatDenied(() -> contextService.establish(establishment(w, r, otherKind), retry));
        // Positive controls: the unmodified claims resume and retry the same context.
        assertThat(contextService.establish(establishment(w, r, original), resume).contextId().toString())
                .isEqualTo(est.contextId());
        assertThat(contextService.establish(establishment(w, r, original), retry).contextId().toString())
                .isEqualTo(est.contextId());
        assertThat(jdbc.queryForObject("SELECT count(*) FROM invocation_contexts WHERE idempotency_key = 'kind-1' "
                + "AND tenant_id = ?", Integer.class, w.tenant)).isEqualTo(1);
    }

    private org.springframework.security.oauth2.jwt.Jwt jwt(String token, String identityKind) throws Exception {
        Map<String, Object> c = new java.util.HashMap<>(claims(token));
        if (identityKind != null) c.put("identity_kind", identityKind);
        Instant iat = Instant.ofEpochSecond(number(c, "iat"));
        Instant exp = Instant.ofEpochSecond(number(c, "exp"));
        c.remove("iat");
        c.remove("exp");
        return org.springframework.security.oauth2.jwt.Jwt.withTokenValue(token).header("alg", "RS256")
                .claims(all -> all.putAll(c)).issuedAt(iat).expiresAt(exp).build();
    }

    private InvocationContextService.Establishment establishment(World w, Map<String, Object> row,
                                                                  org.springframework.security.oauth2.jwt.Jwt subject) {
        @SuppressWarnings("unchecked")
        Map<String, Object> act = (Map<String, Object>) subject.getClaims().get("act");
        return new InvocationContextService.Establishment(w.tenant, w.broker.clientId(), (UUID) row.get("broker_id"),
                w.gatewayAud, (UUID) row.get("gateway_route_id"), subject, (String) act.get("client_id"),
                (UUID) row.get("entry_workload_id"), w.agentAud, Set.of(SCOPE));
    }

    // =================================================================================================================
    // 2. Branch creation serialized with every revocation path
    // =================================================================================================================

    @Test
    void branchCommittedDuringARootRevokeIsInsideTheCascade() throws Exception {
        World w = world("icx-a");
        Established est = establish(w, enter(w, "claims", member(w, "claims")), Map.of());
        Race race = branchThenRevoke(w, est.token(), w.agent, w.gatewayAud, () -> revokeContext(w, est.contextId()));
        assertThat(race.branch().getResponse().getStatus()).isEqualTo(200);
        assertThat(race.revoke().getResponse().getStatus()).isEqualTo(200);
        assertTreeHasNoActiveRow(est.contextId());
        denied(exchange(w.broker, token(race.branch()), w.toolAud, SCOPE, Map.of()), "invalid_grant");
    }

    @Test
    void branchRequestedDuringARootRevokeIsRefusedAndNeverInserted() throws Exception {
        World w = world("icx-a");
        Established est = establish(w, enter(w, "claims", member(w, "claims")), Map.of());
        ExecutorService pool = Executors.newFixedThreadPool(2);
        try {
            barrier.arm(InvocationContextRaceProbe.REVOKE_LOCKED);
            Future<MvcResult> revoke = pool.submit(() -> revokeContext(w, est.contextId()));
            barrier.awaitReached();
            Future<MvcResult> branch = pool.submit(() -> exchange(w.agent, est.token(), w.gatewayAud, SCOPE,
                    Map.of("invocation_branch", "late")));
            awaitLockWaiter();
            barrier.release();
            assertThat(revoke.get(60, TimeUnit.SECONDS).getResponse().getStatus()).isEqualTo(200);
            denied(branch.get(60, TimeUnit.SECONDS), "invalid_grant");
        } finally {
            pool.shutdownNow();
        }
        assertThat(jdbc.queryForObject("SELECT count(*) FROM invocation_contexts WHERE parent_id = ?::uuid", Integer.class,
                est.contextId())).isZero();
    }

    @Test
    void grandchildCommittedDuringABranchRevokeIsInsideThatBranchsCascade() throws Exception {
        World w = world("icx-a");
        Established est = establish(w, enter(w, "claims", member(w, "claims")), Map.of());
        String branch = token(exchange(w.agent, est.token(), w.gatewayAud, SCOPE, Map.of("invocation_branch", "b1")));
        String branchId = (String) claims(branch).get("ctx");
        Race race = branchThenRevoke(w, branch, w.broker, w.agent2Aud, () -> revokeContext(w, branchId));
        assertThat(race.branch().getResponse().getStatus()).isEqualTo(200);
        String grandchild = (String) claims(token(race.branch())).get("ctx");
        assertThat(row(grandchild)).containsEntry("status", "REVOKED");
        assertThat(row(branchId)).containsEntry("status", "REVOKED");
        assertThat(row(est.contextId())).containsEntry("status", "ACTIVE");
        // Self-first chain order for a depth-2 context: grandchild, branch, root.
        List<InvocationContext> chain = repository.chain(UUID.fromString(grandchild), w.tenant);
        assertThat(chain.stream().map(c -> c.getId().toString()).toList())
                .containsExactly(grandchild, branchId, est.contextId());
        InvocationContextService.requireChainShape(chain, UUID.fromString(grandchild));
    }

    @Test
    void branchCommittedDuringASessionRevokeIsInsideTheCascade() throws Exception {
        World w = world("icx-a");
        Entry e = enter(w, "claims", member(w, "claims"));
        Established est = establish(w, e, Map.of());
        long revision = jdbc.queryForObject("SELECT revision FROM iam_sessions WHERE id = ?::uuid", Long.class, e.rootSession());
        Race race = branchThenRevoke(w, est.token(), w.agent, w.gatewayAud, () -> send(post(base(w) + "/sessions/"
                + e.rootSession() + "/revoke"), w.admin, Map.of("expectedRevision", revision)));
        assertThat(race.branch().getResponse().getStatus()).isEqualTo(200);
        assertThat(race.revoke().getResponse().getStatus()).isEqualTo(200);
        assertTreeHasNoActiveRow(est.contextId());
    }

    @Test
    void branchCommittedDuringAnIdentityDisableIsInsideTheCascade() throws Exception {
        World w = world("icx-a");
        String user = member(w, "claims");
        Established est = establish(w, enter(w, "claims", user), Map.of());
        Race race = branchThenRevoke(w, est.token(), w.agent, w.gatewayAud,
                () -> send(put("/users/" + user), w.admin, Map.of("isActive", false)));
        assertThat(race.revoke().getResponse().getStatus()).isEqualTo(200);
        // The branch row committed first and is inside the subject cascade. Its token, if any, is unusable: here token
        // issuance itself then finds the principal disabled and returns no token (pre-existing disabled-principal path).
        assertTreeHasNoActiveRow(est.contextId());
        MvcResult branch = race.branch();
        if (branch.getResponse().getStatus() == 200) {
            denied(exchange(w.broker, token(branch), w.toolAud, SCOPE, Map.of()), "invalid_grant");
        } else {
            assertThat(branch.getResponse().getContentAsString()).doesNotContain("access_token");
        }
    }

    // =================================================================================================================
    // 3. Chain shape
    // =================================================================================================================

    @Test
    void anOutOfOrderChainFailsClosed() throws Exception {
        World w = world("icx-a");
        Established est = establish(w, enter(w, "claims", member(w, "claims")), Map.of());
        String branchId = (String) claims(token(exchange(w.agent, est.token(), w.gatewayAud, SCOPE,
                Map.of("invocation_branch", "shape")))).get("ctx");
        List<InvocationContext> chain = repository.chain(UUID.fromString(branchId), w.tenant);
        assertThat(chain).hasSize(2);
        InvocationContextService.requireChainShape(chain, UUID.fromString(branchId));
        List<InvocationContext> reversed = List.of(chain.get(1), chain.get(0));
        assertThatDenied(() -> InvocationContextService.requireChainShape(reversed, UUID.fromString(branchId)));
        assertThatDenied(() -> InvocationContextService.requireChainShape(List.of(chain.get(0)), UUID.fromString(branchId)));
    }

    // =================================================================================================================
    // Barrier choreography
    // =================================================================================================================

    record Race(MvcResult branch, MvcResult revoke) {}

    interface Call { MvcResult run() throws Exception; }

    /**
     * Branch first: hold the branch transaction after its row is inserted (root lock held, not committed); start the
     * revocation and wait until PostgreSQL shows it blocked on the lock; then let the branch commit.
     */
    private Race branchThenRevoke(World w, String subject, Svc requester, String audience, Call revocation)
            throws Exception {
        ExecutorService pool = Executors.newFixedThreadPool(2);
        try {
            barrier.arm(InvocationContextRaceProbe.BRANCH_INSERTED);
            Future<MvcResult> branch = pool.submit(() -> exchange(requester, subject, audience, SCOPE,
                    Map.of("invocation_branch", "racing")));
            barrier.awaitReached();
            Future<MvcResult> revoke = pool.submit(revocation::run);
            awaitLockWaiter();
            assertThat(revoke.isDone()).as("revocation must wait for the branch transaction").isFalse();
            barrier.release();
            return new Race(branch.get(60, TimeUnit.SECONDS), revoke.get(60, TimeUnit.SECONDS));
        } finally {
            pool.shutdownNow();
        }
    }

    /** Condition, not time: a backend of this database is waiting on a row lock. */
    private void awaitLockWaiter() throws InterruptedException {
        for (int i = 0; i < 1000; i++) {
            Integer waiting = jdbc.queryForObject("SELECT count(*) FROM pg_stat_activity WHERE datname = current_database() "
                    + "AND wait_event_type = 'Lock' AND pid <> pg_backend_pid()", Integer.class);
            if (waiting != null && waiting > 0) return;
            Thread.sleep(10);
        }
        throw new AssertionError("no transaction ever waited on the root lock");
    }

    private void assertTreeHasNoActiveRow(String rootId) {
        Integer active = jdbc.queryForObject("SELECT count(*) FROM invocation_contexts WHERE root_id = ?::uuid "
                + "AND status = 'ACTIVE'", Integer.class, rootId);
        Integer total = jdbc.queryForObject("SELECT count(*) FROM invocation_contexts WHERE root_id = ?::uuid",
                Integer.class, rootId);
        assertThat(total).as("root plus the racing branch").isGreaterThanOrEqualTo(2);
        assertThat(active).as("no ACTIVE row outside the revocation cascade").isZero();
    }

    private static void assertThatDenied(Runnable r) {
        try {
            r.run();
        } catch (InvocationContextService.Denied expected) {
            return;
        }
        throw new AssertionError("expected a fail-closed denial");
    }
}
