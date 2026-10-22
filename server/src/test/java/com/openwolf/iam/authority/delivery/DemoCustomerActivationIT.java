package com.openwolf.iam.authority.delivery;

import com.fasterxml.jackson.databind.JsonNode;
import com.openwolf.iam.IamApplication;
import com.openwolf.iam.authority.AuthorityITSupport;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;

import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;

@SpringBootTest(classes = IamApplication.class, webEnvironment = SpringBootTest.WebEnvironment.MOCK,
        properties = {"iam.ciam.demo-admin-activation.enabled=true",
                "iam.ciam.demo-admin-activation.allowed-tenant=p3-demo-act",
                "iam.ciam.demo-admin-activation.allowed-email-domain=p3.invalid",
                "iam.ciam.demo-admin-activation.allowed-issuer=http://localhost:8084"})
@AutoConfigureMockMvc
class DemoCustomerActivationIT extends AuthorityITSupport {

    @Test
    void platformAdministratorCanActivateOnlyNamedSyntheticProvisionedCustomers() throws Exception {
        Tenant tenant = tenant("p3-demo-act");
        String rootId = "p3-demo-root-" + UUID.randomUUID();
        principal(tenant.id, rootId, "platform_admin");
        String root = login(rootId);
        String first = "first-" + UUID.randomUUID() + "@p3.invalid";
        String second = "second-" + UUID.randomUUID() + "@p3.invalid";
        String otherTenantEmail = "other-" + UUID.randomUUID() + "@p3.invalid";
        String outside = "outside-" + UUID.randomUUID() + "@other.invalid";
        for (String email : List.of(first, second, outside)) {
            body(send(post(base(tenant) + "/ciam/customers"), tenant.admin,
                    Map.of("email", email, "displayName", "Demo", "initialPassword", PASSWORD)), 201);
        }
        Tenant otherTenant = tenant("p3-demo-act-other");
        body(send(post(base(otherTenant) + "/ciam/customers"), otherTenant.admin,
                Map.of("email", otherTenantEmail, "displayName", "Other Tenant", "initialPassword", PASSWORD)), 201);
        String path = base(tenant) + "/ciam/demo-customers/activate";
        assertThat(send(post("/ciam/tenants/" + tenant.id + "/customers/verification-challenges"), null,
                Map.of("email", first)).getResponse().getStatus()).isEqualTo(503);
        assertThat(send(post(path), tenant.admin, Map.of("emails", List.of(first))).getResponse().getStatus())
                .as("tenant admins cannot simulate verification").isEqualTo(403);
        assertThat(send(post(path), null, Map.of("emails", List.of(first))).getResponse().getStatus())
                .as("unauthenticated callers cannot simulate verification").isEqualTo(401);
        assertThat(send(post(path), root, Map.of("emails", List.of(first, outside))).getResponse().getStatus())
                .as("the entire batch is rejected before activating anyone").isEqualTo(409);
        assertThat(send(post(path), root, Map.of("emails", List.of(otherTenantEmail))).getResponse().getStatus())
                .as("a customer in another tenant is never activated").isEqualTo(404);
        assertThat(send(post(base(otherTenant) + "/ciam/demo-customers/activate"), root,
                Map.of("emails", List.of(otherTenantEmail))).getResponse().getStatus())
                .as("the endpoint is restricted to one configured tenant").isEqualTo(404);

        JsonNode activated = body(send(post(path), root, Map.of("emails", List.of(first, second))), 200);
        assertThat(activated).hasSize(2);
        for (JsonNode customer : activated) {
            assertThat(customer.path("status").asText()).isEqualTo("ACTIVE");
            assertThat(customer.path("emailVerifiedAt").isNull()).isFalse();
        }
        assertThat(jdbc.queryForObject("SELECT count(*) FROM customer_identities WHERE tenant_id = ? "
                + "AND email IN (?, ?) AND status = 'ACTIVE' AND email_verified_at IS NOT NULL", Integer.class,
                tenant.id, first, second)).isEqualTo(2);
        assertThat(jdbc.queryForObject("SELECT status FROM customer_identities WHERE tenant_id = ? AND email = ?",
                String.class, tenant.id, outside)).isEqualTo("PENDING_VERIFICATION");
        assertThat(jdbc.queryForObject("SELECT count(*) FROM ciam_lifecycle_events WHERE tenant_id = ? "
                + "AND event_type = 'CUSTOMER_DEMO_ACTIVATED' AND details ->> 'evidence' = 'SIMULATED_DEMO'",
                Integer.class, tenant.id)).isEqualTo(2);
        assertThat(send(post(path), root, Map.of("emails", List.of(first))).getResponse().getStatus())
                .as("already-active identities cannot be activated again").isEqualTo(409);
    }
}
