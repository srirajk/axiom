package com.openwolf.iam.invocation;

import com.openwolf.iam.IamApplication;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;

import java.time.Instant;
import java.util.Map;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Gate B production default: with no agreed verification mechanism the deployed verifier denies every establishment,
 * even with well-formed evidence from the synthetic source, while the Phase 1 exchange path is unchanged.
 */
@SpringBootTest(classes = IamApplication.class, webEnvironment = SpringBootTest.WebEnvironment.MOCK)
@AutoConfigureMockMvc
class InvocationContextDefaultDenyIT extends InvocationContextITSupport {
    @Autowired InvocationAuthorizationVerifier verifier;

    @Test
    void productionVerifierDeniesEveryEstablishment() throws Exception {
        assertThat(verifier).isInstanceOf(DenyingInvocationAuthorizationVerifier.class);
        World w = world("icd-a");
        Entry e = enter(w, "claims", member(w, "claims"));
        String evidence = evidence(w, e, w.agentAud, Set.of(SCOPE), Instant.now().plusSeconds(600));
        denied(exchange(w.broker, e.p3(), w.agentAud, SCOPE, Map.of("invocation_authorization", evidence)), "invalid_grant");
        assertThat(jdbc.queryForObject("SELECT count(*) FROM invocation_contexts WHERE tenant_id = ?", Integer.class, w.tenant))
                .isZero();
        assertThat(jdbc.queryForObject("SELECT count(*) FROM audit_log WHERE tenant_id = ? AND action = 'TOKEN_EXCHANGE_DENIED' "
                + "AND after_state::text LIKE '%no verifiable invocation authorization mechanism%'", Integer.class, w.tenant))
                .isEqualTo(1);
        assertThat(claims(token(exchange(w.broker, e.p3(), w.agentAud, SCOPE, Map.of())))).doesNotContainKey("ctx");
    }
}
