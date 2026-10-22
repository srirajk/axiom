package com.openwolf.iam.authority.delivery;

import com.fasterxml.jackson.databind.JsonNode;
import com.openwolf.iam.IamApplication;
import com.openwolf.iam.authority.AuthorityITSupport;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.web.servlet.MvcResult;

import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;

/**
 * Administrator customer provisioning (B06): an authenticated tenant administrator creates a customer identity that
 * starts pending verification and is marked ADMINISTRATOR. Nothing is verified, no code is issued or returned to the
 * administrator, and the customer cannot sign in until the customer completes the ordinary verification challenge.
 * Runs with the production default (no delivery provider, no local-demo disclosure).
 */
@SpringBootTest(classes = IamApplication.class, webEnvironment = SpringBootTest.WebEnvironment.MOCK)
@AutoConfigureMockMvc
class CustomerAdministratorProvisioningIT extends AuthorityITSupport {

    @Test
    void demoActivationEndpointIsAbsentWithTheDefaultConfiguration() throws Exception {
        Tenant t = tenant("p3b-admprov-default");
        assertThat(send(post(base(t) + "/ciam/demo-customers/activate"), t.admin,
                Map.of("emails", List.of("demo@p3.invalid"))).getResponse().getStatus()).isEqualTo(404);
    }

    @Test
    void anAdministratorProvisionsAnUnverifiedPendingCustomerWithoutSeeingAnyCode() throws Exception {
        Tenant t = tenant("p3b-admprov");
        Tenant other = tenant("p3b-admprov-other");
        String app = app(t, "shop", "https://" + t.s + "-shop.invalid");
        String web = browserClient(t, app, t.s + "-web", List.of(READ));
        String email = "c-" + UUID.randomUUID().toString().substring(0, 8) + "@p3.invalid";
        Map<String, String> request = Map.of("email", email, "displayName", "Provisioned", "initialPassword", PASSWORD);

        MvcResult created = send(post(base(t) + "/ciam/customers"), t.admin, request);
        JsonNode customer = body(created, 201);
        String raw = created.getResponse().getContentAsString();
        assertThat(customer.get("status").asText()).isEqualTo("PENDING_VERIFICATION");
        assertThat(customer.get("provisioningSource").asText()).isEqualTo("ADMINISTRATOR");
        assertThat(customer.get("emailVerifiedAt").isNull()).isTrue();
        assertThat(raw).doesNotContain("localDemoAction").doesNotContain("\"token\"").doesNotContain(PASSWORD);
        UUID id = UUID.fromString(customer.get("customerId").asText());
        assertThat(jdbc.queryForObject("SELECT count(*) FROM customer_identity_challenges WHERE customer_id = ?",
                Integer.class, id)).isZero();
        assertThat(jdbc.queryForObject("SELECT count(*) FROM customer_code_deliveries WHERE tenant_id = ?",
                Integer.class, t.id)).isZero();
        assertThat(auditText(t.id)).contains("ADMINISTRATOR");

        // Pending: the customer cannot sign in.
        assertThat(send(post("/ciam/tenants/" + t.id + "/customers/tokens"), null, Map.of("email", email,
                "password", PASSWORD, "clientId", web, "scopes", List.of(READ))).getResponse().getStatus())
                .isIn(400, 401);
        // Duplicate address, another tenant's administrator, and no authentication are refused.
        assertThat(send(post(base(t) + "/ciam/customers"), t.admin, request).getResponse().getStatus()).isEqualTo(409);
        assertThat(send(post(base(t) + "/ciam/customers"), other.admin, Map.of("email", "x" + email,
                "displayName", "X", "initialPassword", PASSWORD)).getResponse().getStatus()).isEqualTo(403);
        assertThat(send(post(base(t) + "/ciam/customers"), null, request).getResponse().getStatus()).isEqualTo(401);
        // A short initial password is refused by validation.
        assertThat(send(post(base(t) + "/ciam/customers"), t.admin, Map.of("email", "y" + email,
                "displayName", "Y", "initialPassword", "short")).getResponse().getStatus()).isEqualTo(400);
    }

    @Test
    void existingIdentitiesDefaultToSelfRegistration() throws Exception {
        Tenant t = tenant("p3b-admprov");
        UUID existing = UUID.randomUUID();
        jdbc.update("INSERT INTO customer_identities (id, tenant_id, email, display_name, password_hash, status, "
                + "token_version, created_at, updated_at, revision) VALUES (?, ?, ?, 'S', 'x', "
                + "'PENDING_VERIFICATION', 1, now(), now(), 0)", existing, t.id, "s-" + existing + "@p3.invalid");
        JsonNode list = body(send(get(base(t) + "/ciam/customers"), t.admin, null), 200);
        JsonNode found = null;
        for (JsonNode c : list) if (c.get("customerId").asText().equals(existing.toString())) found = c;
        assertThat(found).isNotNull();
        assertThat(found.get("provisioningSource").asText()).isEqualTo("SELF_REGISTRATION");
    }
}
