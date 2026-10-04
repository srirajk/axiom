package com.openwolf.iam.authority.delivery;

import com.fasterxml.jackson.databind.JsonNode;
import com.openwolf.iam.IamApplication;
import com.openwolf.iam.authority.AuthorityITSupport;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.WebApplicationType;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.context.annotation.Import;
import org.springframework.test.web.servlet.MvcResult;

import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;

/**
 * Phase 3.1 with a (synthetic, test-only) provider: codes are delivered through the adapter, never returned; delivery
 * state is durable, retried, bounded and erased; a code verifies once, never after expiry, and never under concurrency
 * twice; delivery failure never looks like verification. The provider here stands in for a real one only.
 */
@SpringBootTest(classes = IamApplication.class, webEnvironment = SpringBootTest.WebEnvironment.MOCK)
@AutoConfigureMockMvc
@Import(SyntheticCustomerCodeDeliveryProvider.Config.class)
@ExtendWith(OutputCaptureExtension.class)
class CustomerCodeDeliveryIT extends AuthorityITSupport {
    private static final CustomerCodeDeliveryProvider.Purpose VERIFY = CustomerCodeDeliveryProvider.Purpose.EMAIL_VERIFICATION;
    private static final CustomerCodeDeliveryProvider.Purpose RECOVER = CustomerCodeDeliveryProvider.Purpose.PASSWORD_RECOVERY;

    @Autowired CustomerCodeDeliveryService deliveries;

    @BeforeEach
    void resetProvider() {
        SyntheticCustomerCodeDeliveryProvider.reset();
    }

    @Test
    void registrationDeliversThroughTheProviderAndTheCodeVerifiesOnce(CapturedOutput output) throws Exception {
        Tenant t = tenant("p3b-a");
        String email = email();
        JsonNode registered = register(t, email);
        assertThat(registered.path("codeDelivery").asText()).isEqualTo("QUEUED");
        assertThat(registered.path("localDemoAction").isNull()).isTrue();
        assertThat(registered.path("customer").path("status").asText()).isEqualTo("PENDING_VERIFICATION");
        String code = SyntheticCustomerCodeDeliveryProvider.latest(email, VERIFY);
        assertThat(code).as("delivered by the provider after commit").isNotNull();
        assertThat(registered.toString()).doesNotContain(code);
        Map<String, Object> delivery = deliveryFor(email);
        assertThat(delivery).containsEntry("status", "SENT").containsEntry("protected_code", null)
                .containsEntry("provider", "synthetic-test-provider");

        JsonNode verified = body(verify(t, code), 200);
        assertThat(verified.path("status").asText()).isEqualTo("ACTIVE");
        assertThat(customerStatus(t, email)).as("persisted, not just reported").isEqualTo("ACTIVE");
        assertThat(verify(t, code).getResponse().getStatus()).as("one use only").isEqualTo(409);

        // Safe logging and evidence: the code never appears in logs, audit, lifecycle events or delivery state.
        assertThat(output.getAll()).doesNotContain(code);
        assertThat(auditText(t.id)).doesNotContain(code).doesNotContain(email);
        assertThat(String.join("|", jdbc.queryForList("SELECT coalesce(protected_code,'') || coalesce(last_failure,'') "
                + "|| coalesce(provider_message_ref,'') FROM customer_code_deliveries", String.class))).doesNotContain(code);
    }

    @Test
    void transientFailureIsRetriedAndOnlyDeliveryNeverVerifies() throws Exception {
        Tenant t = tenant("p3b-a");
        String email = email();
        SyntheticCustomerCodeDeliveryProvider.TRANSIENT_FAILURES.set(1);
        register(t, email);
        assertThat(SyntheticCustomerCodeDeliveryProvider.latest(email, VERIFY)).as("first attempt failed").isNull();
        Map<String, Object> pending = deliveryFor(email);
        assertThat(pending).containsEntry("status", "PENDING").containsEntry("attempts", 1)
                .containsEntry("last_failure", "transient_failure");
        assertThat(pending.get("protected_code")).as("encrypted while pending").isNotNull();
        assertThat(customerStatus(t, email)).as("failure is not verification").isEqualTo("PENDING_VERIFICATION");

        assertThat(deliveries.runDue(50)).isGreaterThanOrEqualTo(1);
        String code = SyntheticCustomerCodeDeliveryProvider.latest(email, VERIFY);
        assertThat(code).isNotNull();
        assertThat(deliveryFor(email)).containsEntry("status", "SENT").containsEntry("attempts", 2)
                .containsEntry("protected_code", null);
        body(verify(t, code), 200);
    }

    @Test
    void exhaustedOrPermanentFailureAbandonsAndErasesTheCode() throws Exception {
        Tenant t = tenant("p3b-a");
        String exhausted = email();
        SyntheticCustomerCodeDeliveryProvider.TRANSIENT_FAILURES.set(10);
        register(t, exhausted);
        deliveries.runDue(50);
        deliveries.runDue(50);
        deliveries.runDue(50);
        assertThat(deliveryFor(exhausted)).containsEntry("status", "ABANDONED").containsEntry("attempts", 3)
                .containsEntry("protected_code", null);
        assertThat(SyntheticCustomerCodeDeliveryProvider.latest(exhausted, VERIFY)).isNull();
        assertThat(customerStatus(t, exhausted)).isEqualTo("PENDING_VERIFICATION");

        SyntheticCustomerCodeDeliveryProvider.reset();
        String rejected = email();
        SyntheticCustomerCodeDeliveryProvider.PERMANENT_FAILURES.set(1);
        register(t, rejected);
        assertThat(deliveryFor(rejected)).containsEntry("status", "ABANDONED").containsEntry("attempts", 1)
                .containsEntry("last_failure", "permanent_failure").containsEntry("protected_code", null);
        assertThat(customerStatus(t, rejected)).isEqualTo("PENDING_VERIFICATION");

        // A resend recovers the stuck customer through a new code; the abandoned one never existed for anyone.
        body(send(post("/ciam/tenants/" + t.id + "/customers/verification-challenges"), null,
                Map.of("email", rejected)), 202);
        String code = SyntheticCustomerCodeDeliveryProvider.latest(rejected, VERIFY);
        assertThat(code).isNotNull();
        body(verify(t, code), 200);
    }

    @Test
    void expiredCodesAndSupersededCodesFail() throws Exception {
        Tenant t = tenant("p3b-a");
        String email = email();
        register(t, email);
        String first = SyntheticCustomerCodeDeliveryProvider.latest(email, VERIFY);
        body(send(post("/ciam/tenants/" + t.id + "/customers/verification-challenges"), null, Map.of("email", email)), 202);
        String second = SyntheticCustomerCodeDeliveryProvider.latest(email, VERIFY);
        assertThat(second).isNotEqualTo(first);
        assertThat(verify(t, first).getResponse().getStatus()).as("superseded").isEqualTo(409);

        jdbc.update("UPDATE customer_identity_challenges SET expires_at = now() - interval '1 second' "
                + "WHERE used_at IS NULL AND customer_id = (SELECT id FROM customer_identities WHERE email = ?)", email);
        assertThat(verify(t, second).getResponse().getStatus()).as("expired").isEqualTo(409);
        assertThat(customerStatus(t, email)).isEqualTo("PENDING_VERIFICATION");
    }

    @Test
    void concurrentUseOfOneCodeSucceedsExactlyOnce() throws Exception {
        Tenant t = tenant("p3b-a");
        String email = email();
        register(t, email);
        String code = SyntheticCustomerCodeDeliveryProvider.latest(email, VERIFY);
        List<Integer> statuses = parallel(8, i -> verify(t, code).getResponse().getStatus());
        assertThat(statuses.stream().filter(s -> s == 200).count()).isEqualTo(1);
        assertThat(statuses).containsOnly(200, 409);
    }

    @Test
    void recoveryIsEnumerationResistantBoundedAndSingleUse() throws Exception {
        Tenant t = tenant("p3b-a");
        String email = email();
        register(t, email);
        body(verify(t, SyntheticCustomerCodeDeliveryProvider.latest(email, VERIFY)), 200);

        JsonNode known = body(recoveryChallenge(t, email), 202);
        JsonNode unknown = body(recoveryChallenge(t, "nobody-" + UUID.randomUUID() + "@p3.invalid"), 202);
        assertThat(known).isEqualTo(unknown);
        assertThat(known.path("codeDelivery").asText()).isEqualTo("QUEUED");
        String recovery = SyntheticCustomerCodeDeliveryProvider.latest(email, RECOVER);
        assertThat(recovery).isNotNull();

        // Issuance limit (3/hour in this fixture): further requests are accepted identically but issue nothing.
        body(recoveryChallenge(t, email), 202);
        body(recoveryChallenge(t, email), 202);
        int before = SyntheticCustomerCodeDeliveryProvider.CALLS.get();
        assertThat(body(recoveryChallenge(t, email), 202)).isEqualTo(unknown);
        assertThat(SyntheticCustomerCodeDeliveryProvider.CALLS.get()).isEqualTo(before);
        assertThat(jdbc.queryForObject("SELECT count(*) FROM customer_identity_challenges c JOIN customer_identities i "
                + "ON i.id = c.customer_id WHERE i.email = ? AND c.challenge_type = 'PASSWORD_RECOVERY'", Integer.class, email))
                .isEqualTo(3);

        String latest = SyntheticCustomerCodeDeliveryProvider.latest(email, RECOVER);
        body(send(post("/ciam/tenants/" + t.id + "/customers/recoveries"), null,
                Map.of("token", latest, "newPassword", "a-new-" + PASSWORD)), 200);
        assertThat(send(post("/ciam/tenants/" + t.id + "/customers/recoveries"), null,
                Map.of("token", latest, "newPassword", "again-" + PASSWORD)).getResponse().getStatus()).isEqualTo(409);
        assertThat(send(post("/ciam/tenants/" + t.id + "/customers/recoveries"), null,
                Map.of("token", recovery, "newPassword", "older-" + PASSWORD)).getResponse().getStatus())
                .as("superseded recovery code").isEqualTo(409);
    }

    @Test
    void pendingDeliverySurvivesARestartAndIsCompletedByTheNewInstance() throws Exception {
        Tenant t = tenant("p3b-a");
        String email = email();
        SyntheticCustomerCodeDeliveryProvider.TRANSIENT_FAILURES.set(1);
        register(t, email);
        assertThat(deliveryFor(email)).containsEntry("status", "PENDING");
        try (ConfigurableApplicationContext restarted = new SpringApplicationBuilder(IamApplication.class,
                SyntheticCustomerCodeDeliveryProvider.Config.class).web(WebApplicationType.SERVLET).run(commandLine())) {
            assertThat(restarted.getBean(CustomerCodeDeliveryService.class).runDue(50)).isGreaterThanOrEqualTo(1);
        }
        assertThat(deliveryFor(email)).containsEntry("status", "SENT");
        body(verify(t, SyntheticCustomerCodeDeliveryProvider.latest(email, VERIFY)), 200);
    }

    @Test
    void databaseOutageRegistersNothingAndReportsNoDelivery() throws Exception {
        Tenant t = tenant("p3b-a");
        String email = email();
        pause(POSTGRES);
        try {
            try {
                MvcResult r = send(post("/ciam/tenants/" + t.id + "/customers/registrations"), null,
                        Map.of("email", email, "displayName", "Outage", "password", PASSWORD));
                assertThat(r.getResponse().getStatus()).isGreaterThanOrEqualTo(500);
                assertThat(r.getResponse().getContentAsString()).doesNotContain("QUEUED");
            } catch (Exception aborted) {
                // The request aborted inside the filter chain: nothing was reported.
            }
        } finally {
            unpause(POSTGRES);
        }
        awaitDatabase();
        assertThat(SyntheticCustomerCodeDeliveryProvider.latest(email, VERIFY)).isNull();
        assertThat(jdbc.queryForObject("SELECT count(*) FROM customer_identities WHERE email = ?", Integer.class, email))
                .isZero();
    }

    // =================================================================================================================

    private JsonNode register(Tenant t, String email) throws Exception {
        return body(send(post("/ciam/tenants/" + t.id + "/customers/registrations"), null,
                Map.of("email", email, "displayName", "Customer", "password", PASSWORD)), 201);
    }

    private MvcResult verify(Tenant t, String code) throws Exception {
        return send(post("/ciam/tenants/" + t.id + "/customers/verifications"), null, Map.of("token", code));
    }

    private MvcResult recoveryChallenge(Tenant t, String email) throws Exception {
        return send(post("/ciam/tenants/" + t.id + "/customers/recovery-challenges"), null, Map.of("email", email));
    }

    private Map<String, Object> deliveryFor(String email) {
        return jdbc.queryForMap("SELECT d.* FROM customer_code_deliveries d JOIN customer_identities i "
                + "ON i.id = d.customer_id WHERE i.email = ? ORDER BY d.created_at DESC LIMIT 1", email);
    }

    private String customerStatus(Tenant t, String email) {
        return jdbc.queryForObject("SELECT status FROM customer_identities WHERE tenant_id = ? AND email = ?",
                String.class, t.id, email);
    }

    private static String email() {
        return "c-" + UUID.randomUUID().toString().substring(0, 8) + "@p3.invalid";
    }
}
