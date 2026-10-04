package com.openwolf.iam.authority.delivery;

import com.openwolf.iam.IamApplication;
import com.openwolf.iam.authority.AuthorityITSupport;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.web.servlet.MvcResult;

import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;

/**
 * Phase 3.1 production default: no provider is configured and local-demo disclosure is off. Every flow that needs a
 * code is refused before any customer, challenge or delivery is created; nothing claims a code was sent, and the
 * refusal is identical for known and unknown addresses.
 */
@SpringBootTest(classes = IamApplication.class, webEnvironment = SpringBootTest.WebEnvironment.MOCK)
@AutoConfigureMockMvc
class CustomerCodeNoProviderIT extends AuthorityITSupport {

    @Test
    void codeDependentCustomerFlowsAreRefusedWithoutAProvider() throws Exception {
        Tenant t = tenant("p3b-none");
        String email = "c-" + UUID.randomUUID().toString().substring(0, 8) + "@p3.invalid";
        MvcResult registration = send(post("/ciam/tenants/" + t.id + "/customers/registrations"), null,
                Map.of("email", email, "displayName", "Customer", "password", PASSWORD));
        assertThat(registration.getResponse().getStatus()).isEqualTo(503);
        assertThat(registration.getResponse().getContentAsString()).doesNotContain("QUEUED").doesNotContain("token");
        assertThat(jdbc.queryForObject("SELECT count(*) FROM customer_identities WHERE email = ?", Integer.class, email))
                .isZero();

        // An existing ACTIVE customer (created out of band) cannot be told apart from an unknown address.
        UUID existing = UUID.randomUUID();
        String known = "k-" + UUID.randomUUID().toString().substring(0, 8) + "@p3.invalid";
        jdbc.update("INSERT INTO customer_identities (id, tenant_id, email, display_name, password_hash, status, "
                + "email_verified_at, token_version, created_at, updated_at, revision) VALUES (?, ?, ?, 'K', 'x', 'ACTIVE', "
                + "now(), 0, now(), now(), 0)", existing, t.id, known);
        MvcResult knownRecovery = send(post("/ciam/tenants/" + t.id + "/customers/recovery-challenges"), null,
                Map.of("email", known));
        MvcResult unknownRecovery = send(post("/ciam/tenants/" + t.id + "/customers/recovery-challenges"), null,
                Map.of("email", "u-" + known));
        assertThat(knownRecovery.getResponse().getStatus()).isEqualTo(503);
        assertThat(unknownRecovery.getResponse().getStatus()).isEqualTo(503);
        assertThat(send(post("/ciam/tenants/" + t.id + "/customers/verification-challenges"), null,
                Map.of("email", known)).getResponse().getStatus()).isEqualTo(503);
        assertThat(jdbc.queryForObject("SELECT count(*) FROM customer_identity_challenges WHERE customer_id = ?",
                Integer.class, existing)).isZero();
        assertThat(jdbc.queryForObject("SELECT count(*) FROM customer_code_deliveries WHERE tenant_id = ?",
                Integer.class, t.id)).isZero();
    }
}
