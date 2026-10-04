package com.openwolf.iam.authority.issuer;

import com.fasterxml.jackson.databind.JsonNode;
import com.openwolf.iam.IamApplication;
import com.openwolf.iam.authority.AuthorityITSupport;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MvcResult;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;

/**
 * Generic issuer repairs (integration-scenario Package B): durable session revocation on RFC 7009 revocation and OIDC
 * logout; client disable ends issued sessions; a status path and a short lifetime for client-credentials tokens
 * (without inventing a human session); discovery advertises only supported grants and client-authentication methods;
 * signing-key changes are platform-administrator only.
 */
@SpringBootTest(classes = IamApplication.class, webEnvironment = SpringBootTest.WebEnvironment.MOCK)
@AutoConfigureMockMvc
class IssuerLifecycleRepairIT extends AuthorityITSupport {
    static final String CALLBACK = "http://127.0.0.1:9/callback";
    static final String ADMIN_CALLBACK = "http://localhost:5180/callback";

    @Test
    void aReplayedAuthorizationCodeEndsTheFirstRedemptionsSession() throws Exception {
        Tenant t = tenant("p3x-a");
        String alice = principal(t.id, t.s + "-alice", null);
        String verifier = "v".repeat(10) + java.util.UUID.randomUUID() + java.util.UUID.randomUUID();
        String challenge = java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(java.security.MessageDigest
                .getInstance("SHA-256").digest(verifier.getBytes(java.nio.charset.StandardCharsets.US_ASCII)));
        MvcResult authorize = mvc.perform(get("/oauth/authorize").queryParam("response_type", "code")
                .queryParam("client_id", "axiom-admin").queryParam("redirect_uri", ADMIN_CALLBACK)
                .queryParam("scope", "openid roles").queryParam("state", "s").queryParam("code_challenge", challenge)
                .queryParam("code_challenge_method", "S256").accept(MediaType.TEXT_HTML).with(user(alice))).andReturn();
        String code = org.springframework.web.util.UriComponentsBuilder.fromUriString(authorize.getResponse()
                .getHeader(HttpHeaders.LOCATION)).build().getQueryParams().getFirst("code");
        String first = tokenResponse(redeem(code, verifier)).path("access_token").asText();
        CodeLogin independent = pkce("axiom-admin", ADMIN_CALLBACK, alice, "openid roles");
        assertThat(send(get("/api/me/sessions"), first, null).getResponse().getStatus()).isEqualTo(200);
        assertThat(redeem(code, verifier).getResponse().getStatus()).as("replay refused").isEqualTo(400);
        assertThat(send(get("/api/me/sessions"), first, null).getResponse().getStatus())
                .as("the token from the first redemption is refused once the code is replayed").isEqualTo(401);
        assertThat(introspect(introspector(t), first).path("active").asBoolean()).isFalse();
        assertThat(send(get("/api/me/sessions"), independent.accessToken(), null).getResponse().getStatus())
                .as("an independent login is unaffected").isEqualTo(200);
    }

    private MvcResult redeem(String code, String verifier) throws Exception {
        return mvc.perform(post("/oauth/token").contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .param("grant_type", "authorization_code").param("client_id", "axiom-admin").param("code", code)
                .param("redirect_uri", ADMIN_CALLBACK).param("code_verifier", verifier)).andReturn();
    }

    @Test
    void oidcLogoutEndsTheDurableSessionNotOnlyTheBrowserSession() throws Exception {
        Tenant t = tenant("p3x-a");
        String bob = principal(t.id, t.s + "-bob", null);
        CodeLogin login = pkce("axiom-admin", ADMIN_CALLBACK, bob, "openid roles");
        CodeLogin other = pkce("axiom-admin", ADMIN_CALLBACK, bob, "openid roles");
        // Relying-party-initiated logout (the browser session itself is exercised by the live Python cookbook).
        // Form POST (OIDC RP-Initiated Logout 1.0 allows POST): the ID token never travels in a URL.
        MvcResult logout = mvc.perform(post("/connect/logout").contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .param("id_token_hint", login.idToken())
                .param("post_logout_redirect_uri", "http://localhost:5180/login")).andReturn();
        assertThat(logout.getResponse().getStatus()).as(String.valueOf(logout.getResponse().getErrorMessage())).isIn(200, 302);
        assertThat(send(get("/api/me/sessions"), login.accessToken(), null).getResponse().getStatus())
                .as("the logged-out session's access token is refused").isEqualTo(401);
        assertThat(introspect(introspector(t), login.accessToken()).path("active").asBoolean()).isFalse();
        assertThat(send(get("/api/me/sessions"), other.accessToken(), null).getResponse().getStatus())
                .as("another authorization of the same person follows its own lifecycle").isEqualTo(200);
    }

    @Test
    void disablingAClientEndsItsIssuedSessions() throws Exception {
        Tenant t = tenant("p3x-a");
        String appId = app(t, "web", "web:" + t.id + ":" + t.s);
        String client = browserClient(t, appId, t.s + "-web", List.of(READ));
        String carol = principal(t.id, t.s + "-carol", null);
        entitle(t, appId, carol, List.of(READ));
        CodeLogin login = pkce(client, CALLBACK, carol, "openid " + READ);
        Svc caller = introspector(t);
        assertThat(introspect(caller, login.accessToken()).path("active").asBoolean()).isTrue();
        String clientRow = jdbc.queryForObject("SELECT id::text FROM tenant_application_clients WHERE client_id = ?",
                String.class, client);
        body(send(delete(base(t) + "/applications/" + appId + "/clients/" + clientRow), t.admin, null), 204);
        assertThat(introspect(caller, login.accessToken()).path("active").asBoolean()).isFalse();
        assertThat(jdbc.queryForObject("SELECT count(*) FROM iam_sessions WHERE client_id = ? AND status = 'ACTIVE'",
                Integer.class, client)).isZero();
    }

    @Test
    void clientCredentialsTokensAreShortLivedAndCarryLiveStatus() throws Exception {
        Tenant t = tenant("p3x-a");
        Svc agent = workload(t, "job", List.of(READ));
        String plainAud = "svc:" + t.id + ":" + t.s;
        Svc plain = confidential(t, app(t, "plain", plainAud), plainAud, t.s + "-plain", List.of(READ));
        Svc caller = introspector(t);
        JsonNode issued = tokenResponse(tokenRequest(agent, Map.of("grant_type", "client_credentials", "scope", READ)));
        assertThat(issued.path("expires_in").asLong()).isBetween(1L, 300L);
        Map<String, Object> claims = claims(issued.path("access_token").asText());
        assertThat(((Number) claims.get("exp")).longValue() - ((Number) claims.get("iat")).longValue()).isLessThanOrEqualTo(300);
        assertThat(claims).doesNotContainKey("sid").containsEntry("identity_kind", "workload");
        String token = issued.path("access_token").asText();
        assertThat(introspect(caller, token).path("active").asBoolean()).as("status path without a session").isTrue();
        String plainToken = clientCredentials(plain, READ);
        assertThat(introspect(caller, plainToken).path("active").asBoolean()).isTrue();

        body(send(post(base(t) + "/ciam/agent-workloads/" + agent.workloadId() + "/suspend"), t.admin, null), 200);
        assertThat(introspect(caller, token).path("active").asBoolean()).as("suspended workload").isFalse();
        assertThat(introspect(caller, plainToken).path("active").asBoolean()).as("unrelated client").isTrue();
        body(send(post(base(t) + "/ciam/agent-workloads/" + agent.workloadId() + "/reactivate"), t.admin, null), 200);
        assertThat(introspect(caller, token).path("active").asBoolean()).isTrue();
        body(send(delete(base(t) + "/applications/" + agent.appId() + "/clients/" + agent.uuid()), t.admin, null), 204);
        assertThat(introspect(caller, token).path("active").asBoolean()).as("disabled client").isFalse();
        assertThat(revoke(plain, plainToken).getResponse().getStatus()).isEqualTo(200);
        assertThat(introspect(caller, plainToken).path("active").asBoolean()).as("revoked token").isFalse();
    }

    @Test
    void introspectionDisclosesNothingAcrossTenants() throws Exception {
        Tenant a = tenant("p3x-a");
        Tenant b = tenant("p3x-c");
        Svc job = workload(a, "job", List.of(READ));
        String token = clientCredentials(job, READ);
        assertThat(introspect(introspector(a), token).path("active").asBoolean()).as("same tenant").isTrue();
        JsonNode foreign = introspect(introspector(b), token);
        assertThat(foreign.path("active").asBoolean()).as("another tenant's client").isFalse();
        assertThat(foreign.has("sub")).isFalse();
    }

    @Test
    void discoveryAdvertisesOnlySupportedCapabilities() throws Exception {
        for (String path : List.of("/.well-known/oauth-authorization-server", "/.well-known/openid-configuration")) {
            JsonNode meta = json.readTree(mvc.perform(get(path)).andReturn().getResponse().getContentAsString());
            List<String> grants = json.convertValue(meta.path("grant_types_supported"), List.class);
            // IDP baseline: refresh_token (confidential web clients granted offline_access) and private_key_jwt
            // (service clients with registered keys) are now supported and therefore advertised; nothing else is added.
            assertThat(grants).as(path).contains("authorization_code", "refresh_token", "client_credentials",
                    "urn:ietf:params:oauth:grant-type:token-exchange").doesNotContain(
                    "urn:ietf:params:oauth:grant-type:device_code", "password").doesNotHaveDuplicates();
            assertThat(json.convertValue(meta.path("token_endpoint_auth_methods_supported"), List.class))
                    .as(path).containsExactlyInAnyOrder("client_secret_basic", "private_key_jwt", "none");
            assertThat(meta.has("dpop_signing_alg_values_supported")).as(path).isFalse();
            assertThat(meta.has("tls_client_certificate_bound_access_tokens")).as(path).isFalse();
            assertThat(meta.has("device_authorization_endpoint")).as(path).isFalse();
        }
        Svc any = introspector(tenant("p3x-a"));
        MvcResult post = mvc.perform(post("/oauth/token").contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .param("grant_type", "client_credentials").param("client_id", any.clientId())
                .param("client_secret", any.secret()).param("scope", READ)).andReturn();
        assertThat(post.getResponse().getStatus()).as("client_secret_post is not supported, as advertised").isEqualTo(401);
    }

    @Test
    void signingKeyChangesArePlatformAdministratorOnly() throws Exception {
        Tenant t = tenant("p3x-b");
        String tenantAdmin = login(principal(t.id, t.s + "-ta", "tenant_admin"));
        assertThat(send(post(base(t) + "/signing-keys"), tenantAdmin, null).getResponse().getStatus()).isEqualTo(403);
        assertThat(send(get(base(t) + "/signing-keys"), tenantAdmin, null).getResponse().getStatus()).isEqualTo(200);
        String platform = login(principal(t.id, t.s + "-pa", "platform_admin"));
        assertThat(send(post(base(t) + "/signing-keys"), platform, null).getResponse().getStatus()).isEqualTo(201);
    }

    // =================================================================================================================

    private Svc introspector(Tenant t) throws Exception {
        String aud = "rs:" + t.id + ":" + t.s + "-" + java.util.UUID.randomUUID().toString().substring(0, 4);
        return confidential(t, app(t, "rs" + java.util.UUID.randomUUID().toString().substring(0, 4), aud), aud,
                t.s + "-rs" + java.util.UUID.randomUUID().toString().substring(0, 4), List.of(READ));
    }

    private MvcResult revoke(Svc caller, String token) throws Exception {
        return mvc.perform(post("/oauth/revoke").contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .header(HttpHeaders.AUTHORIZATION, basic(caller)).param("token", token)
                .param("token_type_hint", "access_token")).andReturn();
    }
}
