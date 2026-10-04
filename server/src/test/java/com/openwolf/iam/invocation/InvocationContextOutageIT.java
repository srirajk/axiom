package com.openwolf.iam.invocation;

import com.openwolf.iam.IamApplication;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.test.web.servlet.MvcResult;
import org.testcontainers.DockerClientFactory;
import org.testcontainers.containers.GenericContainer;

import java.time.Instant;
import java.util.Map;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Gate D — dependency outages. PostgreSQL holds the authoritative context state; Redis holds issued OAuth
 * authorizations. While either is unavailable no context-bound token is issued and no establishment succeeds; after
 * recovery the same, still-active context continues. (The pause makes requests time out rather than refuse
 * immediately; the bounded timeouts are in {@link InvocationContextITSupport#properties()}.)
 */
@SpringBootTest(classes = IamApplication.class, webEnvironment = SpringBootTest.WebEnvironment.MOCK)
@AutoConfigureMockMvc
@Import(SyntheticInvocationAuthorizationVerifier.Config.class)
class InvocationContextOutageIT extends InvocationContextITSupport {

    @Test
    void postgresOutageFailsClosedAndTheContextResumesAfterRecovery() throws Exception {
        World w = world("ico-a");
        Entry e = enter(w, "claims", member(w, "claims"));
        Established est = establish(w, e, Map.of());
        String evidence = evidence(w, e, w.agentAud, Set.of(SCOPE), Instant.now().plusSeconds(600));
        pause(POSTGRES);
        try {
            assertNoToken(() -> exchange(w.agent, est.token(), w.gatewayAud, SCOPE, Map.of()));
            assertNoToken(() -> exchange(w.broker, e.p3(), w.agentAud, SCOPE, Map.of("invocation_authorization", evidence)));
        } finally {
            unpause(POSTGRES);
        }
        awaitDatabase();
        assertThat(claims(token(exchange(w.agent, est.token(), w.gatewayAud, SCOPE, Map.of()))))
                .containsEntry("ctx", est.contextId());
        assertThat(jdbc.queryForObject("SELECT count(*) FROM invocation_contexts WHERE originating_subject = ?",
                Integer.class, e.user())).as("nothing established during the outage").isEqualTo(1);
    }

    @Test
    void redisOutageFailsClosedAndRecovers() throws Exception {
        World w = world("ico-a");
        Established est = establish(w, enter(w, "claims", member(w, "claims")), Map.of());
        pause(REDIS);
        try {
            assertNoToken(() -> exchange(w.agent, est.token(), w.gatewayAud, SCOPE, Map.of()));
        } finally {
            unpause(REDIS);
        }
        Thread.sleep(500);
        assertThat(claims(token(exchange(w.agent, est.token(), w.gatewayAud, SCOPE, Map.of()))))
                .containsEntry("ctx", est.contextId());
    }

    interface Call { MvcResult run() throws Exception; }

    /** Fail closed = no access token, whether the endpoint answers with an error or the request aborts. */
    private void assertNoToken(Call call) {
        try {
            MvcResult r = call.run();
            assertThat(r.getResponse().getStatus()).as(r.getResponse().getContentAsString()).isNotEqualTo(200);
            assertThat(r.getResponse().getContentAsString()).doesNotContain("access_token");
        } catch (AssertionError e) {
            throw e;
        } catch (Exception aborted) {
            // The request failed with an exception inside the filter chain: no token was issued.
        }
    }

    private static void pause(GenericContainer<?> c) {
        DockerClientFactory.instance().client().pauseContainerCmd(c.getContainerId()).exec();
    }

    private static void unpause(GenericContainer<?> c) {
        DockerClientFactory.instance().client().unpauseContainerCmd(c.getContainerId()).exec();
    }

    private void awaitDatabase() throws InterruptedException {
        for (int i = 0; i < 40; i++) {
            try {
                jdbc.queryForObject("SELECT 1", Integer.class);
                return;
            } catch (RuntimeException notYet) {
                Thread.sleep(250);
            }
        }
        throw new AssertionError("database did not recover");
    }
}
