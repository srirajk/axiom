package com.openwolf.iam.authority.consent;

import com.fasterxml.jackson.databind.JsonNode;
import com.openwolf.iam.IamApplication;
import com.openwolf.iam.authority.AuthorityITSupport;
import com.openwolf.iam.authority.delivery.CustomerCodeDeliveryProvider;
import com.openwolf.iam.authority.delivery.SyntheticCustomerCodeDeliveryProvider;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.test.web.servlet.MvcResult;

import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;

/**
 * Phase 3.2: customer consent bound to an exact Agent workload, registered purpose, resource audience, scopes and
 * validity. Wrong purpose, wrong Agent, onward delegation, administrator-fabricated purpose consent, withdrawal,
 * purpose retirement and a database outage all fail closed; consent without a purpose keeps its Phase 1 behaviour.
 */
@SpringBootTest(classes = IamApplication.class, webEnvironment = SpringBootTest.WebEnvironment.MOCK)
@AutoConfigureMockMvc
@Import(SyntheticCustomerCodeDeliveryProvider.Config.class)
class ConsentPurposeIT extends AuthorityITSupport {

    record Fixture(Tenant t, String web, Svc agent, Svc other, UUID customer, String email, String customerToken) {}

    @Test
    void consentIsBoundToTheExactPurposeAgentScopesAndValidity() throws Exception {
        Fixture f = fixture();
        purpose(f, f.agent, "invoice.summary", List.of(READ), 30 * 86400L);
        purpose(f, f.agent, "payment.initiate", List.of(PAY), 86400L);

        // Purpose-bound consent: scope outside the purpose, validity beyond it, or recorded by an administrator fail.
        assertThat(grant(f, f.customerToken, "invoice.summary", List.of(PAY), 86400).getResponse().getStatus()).isEqualTo(400);
        assertThat(grant(f, f.customerToken, "payment.initiate", List.of(PAY), 2 * 86400).getResponse().getStatus())
                .isEqualTo(400);
        // The CIAM chain accepts only customer tokens, so an administrator cannot record consent at all.
        assertThat(grant(f, f.t.admin, "invoice.summary", List.of(READ), 86400).getResponse().getStatus())
                .as("administrator cannot fabricate consent").isIn(401, 403);
        assertThat(grant(f, f.customerToken, "unregistered.purpose", List.of(READ), 86400).getResponse().getStatus())
                .isEqualTo(400);
        JsonNode created = body(grant(f, f.customerToken, "invoice.summary", List.of(READ), 86400), 201);
        assertThat(created.path("purposeCode").asText()).isEqualTo("invoice.summary");
        assertThat(created.path("consentSource").asText()).isEqualTo("CUSTOMER");

        // Exact purpose: the token's purpose is the registered code, not free text.
        String delegated = token(exchange(f.agent, f.customerToken, f.agent.audience(), READ,
                Map.of("delegation_purpose", "invoice.summary")));
        Map<String, Object> claims = claims(delegated);
        assertThat(claims).containsEntry("purpose", "invoice.summary").containsEntry("sub", f.customer.toString())
                .containsEntry("delegation_id", created.path("id").asText());
        assertThat(introspect(f.agent, delegated).path("active").asBoolean()).isTrue();

        // Wrong purpose, wrong scope under the purpose, wrong Agent, onward delegation to another Agent.
        denied(exchange(f.agent, f.customerToken, f.agent.audience(), PAY, Map.of("delegation_purpose", "payment.initiate")),
                "invalid_grant");
        denied(exchange(f.agent, f.customerToken, f.agent.audience(), PAY, Map.of("delegation_purpose", "invoice.summary")),
                "invalid_grant");
        denied(exchange(f.agent, f.customerToken, f.agent.audience(), READ, Map.of("delegation_purpose", "Invoice Summary")),
                "invalid_request");
        assertThat(exchange(f.other, f.customerToken, f.other.audience(), READ,
                Map.of("delegation_purpose", "invoice.summary")).getResponse().getStatus()).isIn(400, 401);
        assertThat(exchange(f.other, delegated, f.other.audience(), READ, Map.of()).getResponse().getStatus())
                .as("customer delegation is not transitive to another Agent").isIn(400, 401);

        // Withdrawal stops renewal (new exchange) and existing authority (introspection) immediately.
        body(send(post("/ciam/tenants/" + f.t.id + "/customers/" + f.customer + "/delegation-grants/"
                + created.path("id").asText() + "/revoke"), f.customerToken, Map.of("reason", "withdrawn")), 200);
        assertThat(introspect(f.agent, delegated).path("active").asBoolean()).isFalse();
        denied(exchange(f.agent, f.customerToken, f.agent.audience(), READ, Map.of("delegation_purpose", "invoice.summary")),
                "invalid_grant");
        assertThat(auditText(f.t.id)).doesNotContain(delegated.substring(delegated.lastIndexOf('.') + 1));
    }

    @Test
    void retiringThePurposeStopsItsGrantsAndPurposesDisambiguateGrants() throws Exception {
        Fixture f = fixture();
        String summary = purpose(f, f.agent, "invoice.summary", List.of(READ), 86400L);
        purpose(f, f.agent, "account.review", List.of(READ), 86400L);
        body(grant(f, f.customerToken, "invoice.summary", List.of(READ), 3600), 201);
        body(grant(f, f.customerToken, "account.review", List.of(READ), 3600), 201);

        // Two consents cover the same Agent/audience/scope: without a purpose the request is ambiguous and refused.
        denied(exchange(f.agent, f.customerToken, f.agent.audience(), READ, Map.of()), "invalid_grant");
        String review = token(exchange(f.agent, f.customerToken, f.agent.audience(), READ,
                Map.of("delegation_purpose", "account.review")));
        String invoice = token(exchange(f.agent, f.customerToken, f.agent.audience(), READ,
                Map.of("delegation_purpose", "invoice.summary")));
        assertThat(claims(review)).containsEntry("purpose", "account.review");

        body(send(post(base(f.t) + "/ciam/agent-workloads/" + f.agent.workloadId() + "/purposes/" + summary + "/retire"),
                f.t.admin, null), 200);
        assertThat(introspect(f.agent, invoice).path("active").asBoolean()).isFalse();
        assertThat(introspect(f.agent, review).path("active").asBoolean()).isTrue();
        denied(exchange(f.agent, f.customerToken, f.agent.audience(), READ, Map.of("delegation_purpose", "invoice.summary")),
                "invalid_grant");
        // The remaining consent now matches alone.
        assertThat(claims(token(exchange(f.agent, f.customerToken, f.agent.audience(), READ, Map.of()))))
                .containsEntry("purpose", "account.review");
    }

    @Test
    void consentWithoutAPurposeKeepsItsExistingBehaviour() throws Exception {
        Fixture f = fixture();
        JsonNode legacy = body(send(post("/ciam/tenants/" + f.t.id + "/customers/" + f.customer + "/delegation-grants"),
                f.customerToken, Map.of("agentWorkloadId", f.agent.workloadId(), "audience", f.agent.audience(),
                        "scopes", List.of(READ), "purpose", "Summarize my invoices",
                        "expiresAt", Instant.now().plusSeconds(3600).toString())), 201);
        assertThat(legacy.path("consentSource").asText()).isEqualTo("CUSTOMER");
        assertThat(legacy.path("purposeCode").isNull()).isTrue();
        String delegated = token(exchange(f.agent, f.customerToken, f.agent.audience(), READ, Map.of()));
        assertThat(claims(delegated)).containsEntry("purpose", "Summarize my invoices");
        denied(exchange(f.agent, f.customerToken, f.agent.audience(), READ, Map.of("delegation_purpose", "invoice.summary")),
                "invalid_grant");
    }

    @Test
    void databaseOutageFailsClosedAndConsentResumesAfterRecovery() throws Exception {
        Fixture f = fixture();
        purpose(f, f.agent, "invoice.summary", List.of(READ), 86400L);
        body(grant(f, f.customerToken, "invoice.summary", List.of(READ), 3600), 201);
        pause(POSTGRES);
        try {
            assertNoToken(() -> exchange(f.agent, f.customerToken, f.agent.audience(), READ,
                    Map.of("delegation_purpose", "invoice.summary")));
        } finally {
            unpause(POSTGRES);
        }
        awaitDatabase();
        assertThat(claims(token(exchange(f.agent, f.customerToken, f.agent.audience(), READ,
                Map.of("delegation_purpose", "invoice.summary"))))).containsEntry("purpose", "invoice.summary");
    }

    // =================================================================================================================

    private Fixture fixture() throws Exception {
        Tenant t = tenant("p3b-c");
        String portalApp = app(t, "portal", "portal:" + t.id + ":" + t.s);
        String web = browserClient(t, portalApp, t.s + "-portal", List.of(READ, WRITE, PAY));
        Svc agent = workload(t, "agent", List.of(READ, WRITE, PAY));
        Svc other = workload(t, "other", List.of(READ, WRITE, PAY));
        String email = "c-" + UUID.randomUUID().toString().substring(0, 8) + "@p3.invalid";
        JsonNode registered = body(send(post("/ciam/tenants/" + t.id + "/customers/registrations"), null,
                Map.of("email", email, "displayName", "Customer", "password", PASSWORD)), 201);
        UUID customer = UUID.fromString(registered.path("customer").path("customerId").asText());
        body(send(post("/ciam/tenants/" + t.id + "/customers/verifications"), null, Map.of("token",
                SyntheticCustomerCodeDeliveryProvider.latest(email, CustomerCodeDeliveryProvider.Purpose.EMAIL_VERIFICATION))), 200);
        String customerToken = body(send(post("/ciam/tenants/" + t.id + "/customers/tokens"), null, Map.of("email", email,
                "password", PASSWORD, "clientId", web, "scopes", List.of(READ, PAY))), 200).path("accessToken").asText();
        return new Fixture(t, web, agent, other, customer, email, customerToken);
    }

    private String purpose(Fixture f, Svc workload, String code, List<String> scopes, long validity) throws Exception {
        return body(send(post(base(f.t) + "/ciam/agent-workloads/" + workload.workloadId() + "/purposes"), f.t.admin,
                Map.of("purposeCode", code, "description", "Purpose " + code, "scopes", scopes,
                        "maxValiditySeconds", validity)), 201).path("id").asText();
    }

    private MvcResult grant(Fixture f, String bearer, String purposeCode, List<String> scopes, long seconds)
            throws Exception {
        Map<String, Object> request = new HashMap<>(Map.of("agentWorkloadId", f.agent.workloadId(),
                "audience", f.agent.audience(), "scopes", scopes, "purpose", "Customer-facing text for " + purposeCode,
                "expiresAt", Instant.now().plusSeconds(seconds).toString()));
        request.put("purposeCode", purposeCode);
        return send(post("/ciam/tenants/" + f.t.id + "/customers/" + f.customer + "/delegation-grants"), bearer, request);
    }
}
