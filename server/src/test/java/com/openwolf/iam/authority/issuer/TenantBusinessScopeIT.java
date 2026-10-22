package com.openwolf.iam.authority.issuer;

import com.fasterxml.jackson.databind.JsonNode;
import com.openwolf.iam.IamApplication;
import com.openwolf.iam.authority.AuthorityITSupport;
import org.junit.jupiter.api.Test;
import org.springframework.boot.WebApplicationType;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;

/**
 * Tenant-scoped, API-managed business-scope vocabulary. Registering a name is vocabulary administration only: it makes the
 * name eligible wherever a business scope is validated in that tenant (client registration, exchange routes, consent
 * purposes, issuance-time entitlement narrowing) and grants no authority to anyone. The deployment's configured scopes
 * remain approved everywhere; unregistered names stay denied.
 */
@SpringBootTest(classes = IamApplication.class, webEnvironment = SpringBootTest.WebEnvironment.MOCK)
@AutoConfigureMockMvc
class TenantBusinessScopeIT extends AuthorityITSupport {
    static final String CALLBACK = "http://127.0.0.1:9/callback";

    private String scopes(Tenant t) { return base(t) + "/business-scopes"; }

    private static String unique(String prefix) {
        return prefix + UUID.randomUUID().toString().replace("-", "").substring(0, 8) + ":invoke";
    }

    @Test
    void anAdministratorRegistersAScopeThatIsUsableAtOnceAndGrantsNothingByItself() throws Exception {
        Tenant t = tenant("tbs-a");
        String scope = unique("quickstart");
        JsonNode created = body(send(post(scopes(t)), t.admin, Map.of("scope", scope, "description", "quickstart call")), 201);
        assertThat(created.path("scope").asText()).isEqualTo(scope);
        assertThat(created.path("tenantId").asText()).isEqualTo(t.id);
        JsonNode listed = body(send(get(scopes(t)), t.admin, null), 200);
        assertThat(listed.path("registered").toString()).contains(scope);
        assertThat(json.convertValue(listed.path("configured"), List.class)).contains(READ, WRITE, PAY);

        // Immediately usable: a client may be registered for it and obtain it (client credentials), no restart.
        String audience = "tbs:" + t.id + ":" + t.s;
        String appId = app(t, "tbs", audience);
        Svc svc = confidential(t, appId, audience, t.s + "-svc", List.of(scope));
        Map<String, Object> claims = claims(clientCredentials(svc, scope));
        assertThat(String.valueOf(claims.get("scope"))).contains(scope);
        // Over-broad: a scope the client is not registered for is refused at the token endpoint.
        denied(tokenRequest(svc, Map.of("grant_type", "client_credentials", "scope", scope + " " + READ)), "invalid_scope");

        // Vocabulary, not authority: a person without the matching permission never receives it in a token.
        String web = t.s + "-web";
        body(send(post(base(t) + "/applications/" + appId + "/clients"), t.admin, Map.of("clientId", web,
                "clientType", "PUBLIC_BROWSER", "redirectUris", List.of(CALLBACK), "postLogoutRedirectUris", List.of(),
                "scopes", List.of("openid", scope, READ))), 201);
        String reader = principal(t.id, t.s + "-rea", null);
        entitle(t, appId, reader, List.of(READ));
        String readerScope = String.valueOf(claims(pkce(web, CALLBACK, reader, "openid " + scope + " " + READ)
                .accessToken()).get("scope"));
        assertThat(readerScope).contains(READ).doesNotContain(scope);
        String caller = principal(t.id, t.s + "-cal", null);
        entitle(t, appId, caller, List.of(scope));
        assertThat(String.valueOf(claims(pkce(web, CALLBACK, caller, "openid " + scope).accessToken()).get("scope")))
                .contains(scope);

        // Other tenant-scoped validation paths accept it in this tenant: an exchange route of a workload.
        Svc workload = workload(t, "wl", List.of(scope));
        String target = "tbs-target:" + t.id + ":" + t.s;
        app(t, "target", target);
        route(t, workload.workloadId(), "RESOURCE", null, target, List.of(scope));

        // Audit: actor, tenant, name and outcome.
        assertThat(auditText(t.id)).contains(scope).contains("CREATED");
    }

    @Test
    void unregisteredNamesStayDeniedAndConfiguredScopesStillWork() throws Exception {
        Tenant t = tenant("tbs-a");
        String audience = "tbs2:" + t.id + ":" + t.s;
        String appId = app(t, "tbs2", audience);
        MvcResult unregistered = send(post(base(t) + "/applications/" + appId + "/clients"), t.admin, Map.of(
                "clientId", t.s + "-un", "clientType", "CONFIDENTIAL_SERVICE", "redirectUris", List.of(),
                "postLogoutRedirectUris", List.of(), "scopes", List.of(unique("never"))));
        assertThat(unregistered.getResponse().getStatus()).isEqualTo(400);
        Svc configured = confidential(t, appId, audience, t.s + "-cfg", List.of(READ));
        assertThat(clientCredentials(configured, READ)).isNotBlank();
    }

    @Test
    void registrationIsIdempotentAndInvalidReservedOrConflictingNamesArePredictable() throws Exception {
        Tenant t = tenant("tbs-a");
        String scope = unique("orders");
        String id = body(send(post(scopes(t)), t.admin, Map.of("scope", scope)), 201).path("id").asText();
        JsonNode again = body(send(post(scopes(t)), t.admin, Map.of("scope", scope)), 200);
        assertThat(again.path("id").asText()).as("same row").isEqualTo(id);
        assertThat(send(post(scopes(t)), t.admin, Map.of("scope", scope, "description", "different"))
                .getResponse().getStatus()).as("conflicting description").isEqualTo(409);
        assertThat(send(post(scopes(t)), t.admin, Map.of("scope", READ)).getResponse().getStatus())
                .as("already a deployment-configured scope").isEqualTo(409);
        for (String bad : List.of("Quickstart:Invoke", "noseparator", "openid", "offline_access", "axiom.platform:x",
                "axiom:anything", "urn:ietf:params:oauth", "trailing:", ":leading", "has space:x", "a*:b",
                "x:" + "y".repeat(130))) {
            assertThat(send(post(scopes(t)), t.admin, Map.of("scope", bad)).getResponse().getStatus())
                    .as(bad).isEqualTo(400);
        }
        assertThat(auditText(t.id)).contains("ALREADY_REGISTERED").contains("REJECTED");
    }

    @Test
    void concurrentRegistrationsOfOneNameCreateExactlyOneRow() throws Exception {
        Tenant t = tenant("tbs-a");
        String scope = unique("race");
        List<Integer> statuses = parallel(8, i -> send(post(scopes(t)), t.admin, Map.of("scope", scope))
                .getResponse().getStatus());
        assertThat(statuses).containsOnly(200, 201);
        assertThat(statuses.stream().filter(s -> s == 201).count()).isEqualTo(1);
        assertThat(jdbc.queryForObject("SELECT count(*) FROM tenant_business_scopes WHERE tenant_id = ? AND scope = ?",
                Integer.class, t.id, scope)).isEqualTo(1);
    }

    @Test
    void catalogsAreTenantPrivateAndAdministrationIsTenantBound() throws Exception {
        Tenant a = tenant("tbs-a");
        Tenant b = tenant("tbs-b");
        String scope = unique("private");
        body(send(post(scopes(a)), a.admin, Map.of("scope", scope)), 201);
        // Forged paths: tenant A's administrator cannot write or read tenant B's catalog.
        assertThat(send(post(scopes(b)), a.admin, Map.of("scope", unique("forged"))).getResponse().getStatus()).isIn(403, 404);
        assertThat(send(get(scopes(b)), a.admin, null).getResponse().getStatus()).isIn(403, 404);
        assertThat(body(send(get(scopes(b)), b.admin, null), 200).path("registered").toString()).doesNotContain(scope);
        // Not approved in tenant B.
        String audience = "tbs3:" + b.id + ":" + b.s;
        String appB = app(b, "tbs3", audience);
        assertThat(send(post(base(b) + "/applications/" + appB + "/clients"), b.admin, Map.of("clientId", b.s + "-x",
                "clientType", "CONFIDENTIAL_SERVICE", "redirectUris", List.of(), "postLogoutRedirectUris", List.of(),
                "scopes", List.of(scope))).getResponse().getStatus()).isEqualTo(400);
        // Unauthenticated and non-administrator callers.
        assertThat(send(get(scopes(a)), null, null).getResponse().getStatus()).isEqualTo(401);
        assertThat(send(post(scopes(a)), null, Map.of("scope", unique("anon"))).getResponse().getStatus()).isEqualTo(401);
        String person = login(principal(a.id, a.s + "-plain", null));
        assertThat(send(post(scopes(a)), person, Map.of("scope", unique("user"))).getResponse().getStatus()).isEqualTo(403);
        assertThat(send(get(scopes(a)), person, null).getResponse().getStatus()).isEqualTo(403);
        // Discovery stays global: configured scopes only, never a tenant's private catalog.
        JsonNode meta = json.readTree(mvc.perform(get("/.well-known/openid-configuration")).andReturn().getResponse()
                .getContentAsString());
        assertThat(meta.path("scopes_supported").toString()).contains(READ).doesNotContain(scope);
    }

    @Test
    void theCatalogSurvivesARestart() throws Exception {
        Tenant t = tenant("tbs-a");
        String scope = unique("durable");
        body(send(post(scopes(t)), t.admin, Map.of("scope", scope)), 201);
        try (ConfigurableApplicationContext restarted = new SpringApplicationBuilder(IamApplication.class)
                .web(WebApplicationType.SERVLET).run(commandLine())) {
            MockMvc fresh = MockMvcBuilders.webAppContextSetup((WebApplicationContext) restarted).apply(springSecurity()).build();
            String audience = "tbs4:" + t.id + ":" + t.s;
            String appId = json.readTree(fresh.perform(post(base(t) + "/applications")
                    .header(HttpHeaders.AUTHORIZATION, "Bearer " + t.admin).contentType(MediaType.APPLICATION_JSON)
                    .content(json.writeValueAsString(Map.of("applicationKey", t.s + "-tbs4", "displayName", "tbs4",
                            "audience", audience)))).andReturn().getResponse().getContentAsString()).path("id").asText();
            MvcResult client = fresh.perform(post(base(t) + "/applications/" + appId + "/clients")
                    .header(HttpHeaders.AUTHORIZATION, "Bearer " + t.admin).contentType(MediaType.APPLICATION_JSON)
                    .content(json.writeValueAsString(Map.of("clientId", t.s + "-dur", "clientType", "CONFIDENTIAL_SERVICE",
                            "redirectUris", List.of(), "postLogoutRedirectUris", List.of(), "scopes", List.of(scope)))))
                    .andReturn();
            assertThat(client.getResponse().getStatus()).as("registered before the restart, usable after it").isEqualTo(201);
            MvcResult listed = fresh.perform(get(scopes(t)).header(HttpHeaders.AUTHORIZATION, "Bearer " + t.admin)).andReturn();
            assertThat(listed.getResponse().getContentAsString()).contains(scope);
        }
        assertThat(jdbc.queryForObject("SELECT count(*) FROM tenant_business_scopes WHERE scope = ?", Integer.class, scope))
                .isEqualTo(1);
    }
}
