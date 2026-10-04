package com.openwolf.iam.authority.delivery;

import com.fasterxml.jackson.databind.JsonNode;
import com.openwolf.iam.IamApplication;
import com.openwolf.iam.authority.AuthorityITSupport;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.boot.WebApplicationType;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;

/**
 * Phase 3.1 demo-disclosure safety. The local-demo disclosure is the only way Axiom ever returns a code, and only:
 * on a stack whose issuer is a loopback host, with no real provider configured, and only for e-mail verification of an
 * account being registered. Recovery codes are never returned (anyone who can reach the endpoint could otherwise take
 * over any account by e-mail address). Any other combination refuses to start.
 */
@SpringBootTest(classes = IamApplication.class, webEnvironment = SpringBootTest.WebEnvironment.MOCK,
        properties = "iam.ciam.local-demo-challenge-disclosure=true")
@AutoConfigureMockMvc
@ExtendWith(OutputCaptureExtension.class)
class CustomerCodeLocalDemoIT extends AuthorityITSupport {

    @Test
    void localDemoNeverDisclosesRecoveryCodesAndLabelsVerificationAsLocalDemo(CapturedOutput output) throws Exception {
        Tenant t = tenant("p3g-c");
        String email = "c-" + UUID.randomUUID().toString().substring(0, 8) + "@p3.invalid";
        JsonNode registered = body(send(post("/ciam/tenants/" + t.id + "/customers/registrations"), null,
                Map.of("email", email, "displayName", "Customer", "password", PASSWORD)), 201);
        assertThat(registered.path("codeDelivery").asText()).isEqualTo("LOCAL_DEMO");
        String code = registered.path("localDemoAction").path("token").asText();
        assertThat(code).as("verification code disclosed only by the local-demo fixture").isNotBlank();
        body(send(post("/ciam/tenants/" + t.id + "/customers/verifications"), null, Map.of("token", code)), 200);

        // Without a real provider recovery is refused — identically for known and unknown addresses, never a code.
        var known = send(post("/ciam/tenants/" + t.id + "/customers/recovery-challenges"), null, Map.of("email", email));
        var unknown = send(post("/ciam/tenants/" + t.id + "/customers/recovery-challenges"), null, Map.of("email", "u-" + email));
        assertThat(known.getResponse().getStatus()).as("recovery code never returned").isEqualTo(503);
        assertThat(unknown.getResponse().getStatus()).isEqualTo(503);
        assertThat(known.getResponse().getContentAsString()).doesNotContain("localDemoAction").doesNotContain("token");
        String recovery = jdbc.queryForObject("SELECT count(*) FROM customer_identity_challenges c JOIN customer_identities i "
                + "ON i.id = c.customer_id WHERE i.email = ? AND c.challenge_type = 'PASSWORD_RECOVERY'", String.class, email);
        assertThat(recovery).as("no recovery challenge exists without a delivery channel").isEqualTo("0");
        assertThat(output.getAll()).doesNotContain(code);
        assertThat(auditText(t.id)).doesNotContain(code);
    }

    @Test
    void disclosureRefusesToStartOnANonLoopbackIssuerOrWithARealProvider() {
        assertThatThrownBy(() -> start(List.of("--iam.ciam.local-demo-challenge-disclosure=true",
                "--spring.security.oauth2.authorizationserver.issuer=https://axiom.example.test")))
                .hasStackTraceContaining("local-demo challenge disclosure");
        assertThatThrownBy(() -> start(List.of("--iam.ciam.local-demo-challenge-disclosure=true",
                "--spring.security.oauth2.authorizationserver.issuer=http://10.0.0.5:8084")))
                .hasStackTraceContaining("local-demo challenge disclosure");
        assertThatThrownBy(() -> new SpringApplicationBuilder(IamApplication.class,
                SyntheticCustomerCodeDeliveryProvider.Config.class).web(WebApplicationType.SERVLET)
                .run(args(List.of("--iam.ciam.local-demo-challenge-disclosure=true"))).close())
                .hasStackTraceContaining("local-demo challenge disclosure");
    }

    private void start(List<String> extra) {
        new SpringApplicationBuilder(IamApplication.class).web(WebApplicationType.SERVLET).run(args(extra)).close();
    }

    private static String[] args(List<String> extra) {
        List<String> all = new ArrayList<>(List.of(commandLine()));
        all.addAll(extra);
        return all.toArray(String[]::new);
    }
}
