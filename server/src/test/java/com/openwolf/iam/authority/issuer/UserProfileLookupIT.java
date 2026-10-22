package com.openwolf.iam.authority.issuer;

import com.fasterxml.jackson.databind.JsonNode;
import com.openwolf.iam.IamApplication;
import com.openwolf.iam.auth.ApplicationScopes;
import com.openwolf.iam.authority.AuthorityITSupport;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;

@SpringBootTest(classes = IamApplication.class, webEnvironment = SpringBootTest.WebEnvironment.MOCK)
@AutoConfigureMockMvc
class UserProfileLookupIT extends AuthorityITSupport {
    @Test
    void authorizationCodeResourceCannotSilentlySelectAnotherAudience() throws Exception {
        Tenant tenant = tenant("resource-guard");
        String audience = "https://api.example.test/primary";
        String appId = app(tenant, "resource-primary", audience);
        String browser = browserClient(tenant, appId, tenant.s + "-resource-browser", List.of(READ));
        JsonNode refused = body(send(get("/oauth/authorize")
                .param("response_type", "code")
                .param("client_id", browser)
                .param("redirect_uri", "http://127.0.0.1:9/callback")
                .param("resource", "https://api.example.test/other"), null, null), 400);
        assertThat(refused.path("error").asText()).isEqualTo("invalid_target");
        JsonNode tokenRefused = body(send(post("/oauth/token")
                .param("grant_type", "authorization_code")
                .param("client_id", browser)
                .param("resource", "https://api.example.test/other"), null, null), 400);
        assertThat(tokenRefused.path("error").asText()).isEqualTo("invalid_target");
    }

    @Test
    void adminApiCreatesAndEditsHumanNamesWithoutChangingSubject() throws Exception {
        Tenant tenant = tenant("profile-admin");
        String id = tenant.s + "-jane";
        JsonNode created = body(send(post("/users"), tenant.admin, Map.of(
                "id", id, "username", id, "password", PASSWORD,
                "email", "jane@example.test", "givenName", "Jane", "familyName", "Brooks")), 201);
        assertThat(created.path("name").asText()).isEqualTo("Jane Brooks");
        assertThat(created.path("id").asText()).isEqualTo(id);

        JsonNode overridden = body(send(org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put("/users/" + id),
                tenant.admin, Map.of("name", "Dr. Jane Brooks")), 200);
        assertThat(overridden.path("name").asText()).isEqualTo("Dr. Jane Brooks");
        JsonNode derived = body(send(org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put("/users/" + id),
                tenant.admin, Map.of("name", "", "givenName", "Janet")), 200);
        assertThat(derived.path("name").asText()).isEqualTo("Janet Brooks");
        assertThat(derived.path("givenName").asText()).isEqualTo("Janet");
    }

    @Test
    void customerProvisioningCanDeriveANameWithoutInventingMissingParts() throws Exception {
        Tenant tenant = tenant("profile-customer");
        JsonNode created = body(send(post(base(tenant) + "/ciam/customers"), tenant.admin, Map.of(
                "email", tenant.s + "@example.test", "initialPassword", PASSWORD,
                "givenName", "Nina", "familyName", "Patel")), 201);
        assertThat(created.path("displayName").asText()).isEqualTo("Nina Patel");
        assertThat(created.path("givenName").asText()).isEqualTo("Nina");
        assertThat(created.path("familyName").asText()).isEqualTo("Patel");
    }

    @Test
    void humanIdTokenAndUserInfoCarryStructuredNameOnlyWithProfileScope() throws Exception {
        Tenant tenant = tenant("profile-oidc");
        String john = principal(tenant.id, tenant.s + "-john", null);
        jdbc.update("UPDATE principals SET attributes = ?::jsonb WHERE id = ?",
                "{\"given_name\":\"John\",\"family_name\":\"Smith\"}", john);
        String audience = "people:" + tenant.id + ":" + tenant.s;
        String appId = app(tenant, "people", audience);
        String browser = browserClient(tenant, appId, tenant.s + "-browser",
                List.of("profile", "email", READ));
        entitle(tenant, appId, john, List.of(READ));

        CodeLogin full = pkce(browser, "http://127.0.0.1:9/callback", john, "openid profile email");
        Map<String, Object> id = claims(full.idToken());
        assertThat(id).containsEntry("name", "John Smith")
                .containsEntry("given_name", "John")
                .containsEntry("family_name", "Smith");
        JsonNode userinfo = body(send(get("/oauth/userinfo"), full.accessToken(), null), 200);
        assertThat(userinfo.path("name").asText()).isEqualTo("John Smith");
        assertThat(userinfo.path("given_name").asText()).isEqualTo("John");
        assertThat(userinfo.path("family_name").asText()).isEqualTo("Smith");

        CodeLogin emailOnly = pkce(browser, "http://127.0.0.1:9/callback", john, "openid email");
        assertThat(claims(emailOnly.idToken())).containsKey("email").doesNotContainKey("name");
        JsonNode emailOnlyInfo = body(send(get("/oauth/userinfo"), emailOnly.accessToken(), null), 200);
        assertThat(emailOnlyInfo.has("name")).isFalse();
        assertThat(emailOnlyInfo.has("given_name")).isFalse();
    }

    @Test
    void serviceLookupAndGroupMembershipAreTenantBoundAndNarrow() throws Exception {
        Tenant home = tenant("profile-a");
        Tenant other = tenant("profile-b");
        String rita = principal(home.id, home.s + "-rita", null);
        String ravi = principal(home.id, home.s + "-ravi", null);
        String outsider = principal(other.id, other.s + "-outside", null);
        jdbc.update("UPDATE principals SET attributes = ?::jsonb WHERE id = ?",
                "{\"given_name\":\"Rita\",\"family_name\":\"Lopez\"}", rita);
        jdbc.update("UPDATE principals SET attributes = ?::jsonb WHERE id = ?",
                "{\"given_name\":\"Ravi\",\"family_name\":\"Kumar\"}", ravi);
        String audience = "profiles:" + home.id + ":" + home.s;
        String appId = app(home, "profiles", audience);
        Svc reader = confidential(home, appId, audience, home.s + "-reader",
                List.of(ApplicationScopes.USERS_READ_PROFILE));
        Svc unprivileged = confidential(home, appId, audience, home.s + "-ordinary", List.of(READ));
        String allowed = clientCredentials(reader, ApplicationScopes.USERS_READ_PROFILE);
        String denied = clientCredentials(unprivileged, READ);
        List<String> subjects = List.of(rita, ravi, outsider, "unknown");
        JsonNode profiles = body(send(post("/admin/users/lookup"), allowed, Map.of("subjects", subjects)), 200);
        assertThat(profiles.size()).isEqualTo(2);
        assertThat(profiles.get(0).path("subject").asText()).isEqualTo(rita);
        assertThat(profiles.get(0).path("name").asText()).isEqualTo("Rita Lopez");
        assertThat(profiles.get(1).path("name").asText()).isEqualTo("Ravi Kumar");
        assertThat(send(post("/admin/users/lookup"), denied, Map.of("subjects", subjects))
                .getResponse().getStatus()).isEqualTo(403);
        assertThat(send(get("/users/" + rita), denied, null).getResponse().getStatus()).isIn(401, 403);
        String ritaLogin = login(rita);
        assertThat(send(get("/users/" + rita), ritaLogin, null).getResponse().getStatus()).isEqualTo(200);
        assertThat(send(get("/users/" + ravi), ritaLogin, null).getResponse().getStatus()).isEqualTo(403);

        JsonNode group = body(send(post("/teams"), home.admin, Map.of("name", home.s + "-reviewers")), 201);
        String groupId = group.path("id").asText();
        body(send(post("/teams/" + groupId + "/members"), home.admin, Map.of("userId", rita)), 201);
        JsonNode members = body(send(get("/admin/groups/" + groupId + "/members"), allowed, null), 200);
        assertThat(members.path("totalElements").asInt()).isEqualTo(1);
        assertThat(members.path("content").size()).isEqualTo(1);
        assertThat(members.path("content").get(0).path("name").asText()).isEqualTo("Rita Lopez");
        body(send(post("/teams/" + groupId + "/members"), home.admin, Map.of("userId", ravi)), 201);
        JsonNode firstPage = body(send(get("/admin/groups/" + groupId + "/members?page=0&size=1"), allowed, null), 200);
        JsonNode secondPage = body(send(get("/admin/groups/" + groupId + "/members?page=1&size=1"), allowed, null), 200);
        assertThat(firstPage.path("totalElements").asInt()).isEqualTo(2);
        assertThat(firstPage.path("hasNext").asBoolean()).isTrue();
        assertThat(secondPage.path("hasNext").asBoolean()).isFalse();
        assertThat(firstPage.path("content").size()).isEqualTo(1);
        assertThat(secondPage.path("content").size()).isEqualTo(1);
        assertThat(firstPage.path("content").get(0).path("subject").asText())
                .isNotEqualTo(secondPage.path("content").get(0).path("subject").asText());
        assertThat(send(get("/admin/groups/" + groupId + "/members?size=101"), allowed, null)
                .getResponse().getStatus()).isEqualTo(400);
        assertThat(send(get("/admin/groups/" + groupId + "/members?page=-1"), allowed, null)
                .getResponse().getStatus()).isEqualTo(400);
        assertThat(send(get("/admin/groups/" + groupId + "/members"), clientCredentials(
                confidential(other, app(other, "other-profiles", "profiles:" + other.id + ":" + other.s),
                        "profiles:" + other.id + ":" + other.s, other.s + "-reader",
                        List.of(ApplicationScopes.USERS_READ_PROFILE)), ApplicationScopes.USERS_READ_PROFILE), null)
                .getResponse().getStatus()).isNotEqualTo(200);
        assertThat(send(get("/admin/groups/" + groupId + "/members"), denied, null)
                .getResponse().getStatus()).isEqualTo(403);
        assertThat(send(get("/teams/" + groupId + "/members"), denied, null)
                .getResponse().getStatus()).isIn(401, 403);

        List<String> tooMany = new ArrayList<>();
        for (int i = 0; i < 201; i++) tooMany.add("subject-" + i);
        assertThat(send(post("/admin/users/lookup"), allowed, Map.of("subjects", tooMany))
                .getResponse().getStatus()).isEqualTo(400);
    }
}
