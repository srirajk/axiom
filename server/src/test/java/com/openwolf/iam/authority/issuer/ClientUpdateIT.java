package com.openwolf.iam.authority.issuer;

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
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.patch;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;

/** PATCH of a tenant application client: scopes, redirects, display name, re-enable; immutables and authorization. */
@SpringBootTest(classes = IamApplication.class, webEnvironment = SpringBootTest.WebEnvironment.MOCK)
@AutoConfigureMockMvc
class ClientUpdateIT extends AuthorityITSupport {
    static final String CALLBACK = "http://127.0.0.1:9/callback";

    private String clientUrl(Tenant t, String appId, String rowId) {
        return base(t) + "/applications/" + appId + "/clients/" + rowId;
    }

    private String webClient(Tenant t, String appId, String clientId, List<String> scopes) throws Exception {
        return body(send(post(base(t) + "/applications/" + appId + "/clients"), t.admin, Map.of("clientId", clientId,
                "clientType", "PUBLIC_BROWSER", "redirectUris", List.of(CALLBACK), "postLogoutRedirectUris", List.of(),
                "scopes", scopes)), 201).path("client").path("id").asText();
    }

    @Test
    void aDisabledClientIsReEnabledWithNewScopesAndItsIdStaysTaken() throws Exception {
        Tenant t = tenant("cu-a");
        String scope = "cu" + UUID.randomUUID().toString().replace("-", "").substring(0, 8) + ":read";
        body(send(post(base(t) + "/business-scopes"), t.admin, Map.of("scope", scope)), 201);
        String appId = app(t, "cu", "cu:" + t.id + ":" + t.s);
        String clientId = t.s + "-web";
        String rowId = webClient(t, appId, clientId, List.of("openid"));

        body(send(delete(clientUrl(t, appId, rowId)), t.admin, null), 204);
        // The id stays taken, which is why an update has to exist.
        assertThat(send(post(base(t) + "/applications/" + appId + "/clients"), t.admin, Map.of("clientId", clientId,
                "clientType", "PUBLIC_BROWSER", "redirectUris", List.of(CALLBACK), "scopes", List.of("openid")))
                .getResponse().getStatus()).isEqualTo(409);

        JsonNode updated = body(send(patch(clientUrl(t, appId, rowId)), t.admin, Map.of("enabled", true,
                "scopes", List.of("openid", "profile", scope), "displayName", "Renamed",
                "redirectUris", List.of("https://app.example.com/cb"))), 200);
        assertThat(updated.path("status").asText()).isEqualTo("ACTIVE");
        assertThat(updated.path("clientId").asText()).isEqualTo(clientId);
        assertThat(json.convertValue(updated.path("scopes"), List.class)).containsExactlyInAnyOrder("openid", "profile", scope);
        assertThat(json.convertValue(updated.path("redirectUris"), List.class)).containsExactly("https://app.example.com/cb");
        assertThat(jdbc.queryForObject("SELECT status FROM tenant_application_clients WHERE client_id = ?", String.class,
                clientId)).isEqualTo("ACTIVE");
        // A fields-absent patch changes nothing; disabling again works.
        JsonNode same = body(send(patch(clientUrl(t, appId, rowId)), t.admin, Map.of()), 200);
        assertThat(same.path("scopes").toString()).contains(scope);
        assertThat(body(send(patch(clientUrl(t, appId, rowId)), t.admin, Map.of("enabled", false)), 200)
                .path("status").asText()).isEqualTo("DISABLED");
        assertThat(auditText(t.id)).contains(scope);
        assertThat(jdbc.queryForObject("SELECT count(*) FROM audit_log WHERE action = 'UPDATE_APPLICATION_CLIENT' AND resource_id = ?",
                Integer.class, rowId)).isEqualTo(3);
    }

    @Test
    void immutableFieldsUnapprovedScopesAndBadInputAreRefused() throws Exception {
        Tenant t = tenant("cu-a");
        String appId = app(t, "cu2", "cu2:" + t.id + ":" + t.s);
        String rowId = webClient(t, appId, t.s + "-web", List.of("openid"));
        String url = clientUrl(t, appId, rowId);
        assertThat(send(patch(url), t.admin, Map.of("clientId", "another-id")).getResponse().getStatus()).isEqualTo(400);
        assertThat(send(patch(url), t.admin, Map.of("clientType", "CONFIDENTIAL_WEB")).getResponse().getStatus()).isEqualTo(400);
        assertThat(send(patch(url), t.admin, Map.of("scopes", List.of("openid", "never:approved"))).getResponse().getStatus())
                .isEqualTo(400);
        assertThat(send(patch(url), t.admin, Map.of("scopes", List.of("profile"))).getResponse().getStatus())
                .as("interactive clients keep openid").isEqualTo(400);
        assertThat(send(patch(url), t.admin, Map.of("redirectUris", List.of("http://evil.example.com/cb"))).getResponse().getStatus())
                .isEqualTo(400);
        assertThat(send(patch(url), t.admin, Map.of("expectedRevision", 999)).getResponse().getStatus()).isEqualTo(409);
        // Nothing changed.
        assertThat(jdbc.queryForObject("SELECT allowed_scopes::text FROM tenant_application_clients WHERE id = ?::uuid",
                String.class, rowId)).contains("openid").doesNotContain("never:approved");
        // A service client takes no browser redirects.
        Svc svc = confidential(t, appId, "x", t.s + "-svc", List.of(READ));
        assertThat(send(patch(clientUrl(t, appId, svc.uuid())), t.admin, Map.of("redirectUris", List.of(CALLBACK)))
                .getResponse().getStatus()).isEqualTo(400);
        assertThat(send(patch(clientUrl(t, appId, svc.uuid())), t.admin, Map.of("scopes", List.of(READ, WRITE)))
                .getResponse().getStatus()).isEqualTo(200);
    }

    @Test
    void callersWithoutTheAdminRoleOrOfAnotherTenantAreRefused() throws Exception {
        Tenant a = tenant("cu-a");
        Tenant b = tenant("cu-b");
        String appId = app(a, "cu3", "cu3:" + a.id + ":" + a.s);
        String rowId = webClient(a, appId, a.s + "-web", List.of("openid"));
        String url = clientUrl(a, appId, rowId);
        Map<String, Object> change = Map.of("scopes", List.of("openid", "profile"));
        assertThat(send(patch(url), null, change).getResponse().getStatus()).isEqualTo(401);
        String person = login(principal(a.id, a.s + "-plain", null));
        assertThat(send(patch(url), person, change).getResponse().getStatus()).isEqualTo(403);
        assertThat(send(patch(url), b.admin, change).getResponse().getStatus()).isIn(403, 404);
        assertThat(jdbc.queryForObject("SELECT allowed_scopes::text FROM tenant_application_clients WHERE id = ?::uuid",
                String.class, rowId)).doesNotContain("profile");
    }
}
