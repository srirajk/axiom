package com.openwolf.iam.authority.issuer;

import com.fasterxml.jackson.databind.JsonNode;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.openwolf.iam.IamApplication;
import com.openwolf.iam.authority.AuthorityITSupport;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.web.util.UriComponentsBuilder;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;

/**
 * IDP baseline repairs, each reproduced before the repair (see the capability ledger): secure defaults for the legacy
 * password-to-token and impersonation endpoints; standard CIAM browser login through a customer-facing client with
 * population separation; standard refresh tokens (offline_access, rotation, reuse withdraws the family, client
 * binding, session withdrawal); private_key_jwt client authentication with single-use assertions; per-client
 * interactive token lifetime; and customer-preserving token exchange and continuation along explicit edges.
 */
@SpringBootTest(classes = IamApplication.class, webEnvironment = SpringBootTest.WebEnvironment.MOCK)
@AutoConfigureMockMvc
class IdpBaselineIT extends AuthorityITSupport {
    static final String CALLBACK = "http://127.0.0.1:9/callback";

    // ---------------------------------------------------------------------------------------------- secure defaults

    @Test
    void legacyPasswordLoginAndImpersonationAreOffByDefault() throws Exception {
        for (String path : new String[]{"/auth/login", "/auth/token"}) {
            int status = mvc.perform(post(path).contentType(MediaType.APPLICATION_JSON)
                    .content(json.writeValueAsString(Map.of("username", "anyone", "password", "irrelevant-12345"))))
                    .andReturn().getResponse().getStatus();
            assertThat(status).as(path + " without explicit opt-in").isEqualTo(404);
        }
        Tenant t = tenant("idp-a");
        String root = principal(t.id, t.s + "-root", "platform_admin");
        int impersonate = send(post("/auth/impersonate"), login(root), Map.of("userId", t.adminId))
                .getResponse().getStatus();
        assertThat(impersonate).as("impersonation without explicit opt-in").isEqualTo(404);
    }

    // ------------------------------------------------------------------------------------- customer browser login

    @Test
    void customerSignsInThroughTheStandardCodeFlowAndPopulationsStaySeparate() throws Exception {
        Tenant t = tenant("idp-a");
        String audience = "shop:" + t.id + ":" + t.s;
        String appId = app(t, "shop", audience);
        String customerClient = interactiveClient(t, appId, t.s + "-shop-web", "PUBLIC_BROWSER", "CUSTOMER",
                List.of("openid", "email", "profile", READ), Map.of());
        Customer c = activeCustomer(t, "carol");

        Login login = customerLogin(customerClient, c, "openid email profile " + READ);
        JsonNode tokens = tokenResponse(redeemPublic(customerClient, login));
        Map<String, Object> access = claims(tokens.get("access_token").asText());
        assertThat(access.get("sub")).isEqualTo(c.id());
        assertThat(audiences(access)).isEqualTo(List.of(audience));
        assertThat(access).containsEntry("identity_kind", "customer").doesNotContainKey("roles")
                .doesNotContainKey("permissions").containsKey("sid").containsKey("auth_time");
        Map<String, Object> id = claims(tokens.get("id_token").asText());
        assertThat(id.get("sub")).isEqualTo(c.id());
        assertThat(id.get("email")).isEqualTo(c.email());
        assertThat(id.get("nonce")).isEqualTo("n-" + login.state());
        assertThat(introspect(introspector(t), tokens.get("access_token").asText()).path("active").asBoolean()).isTrue();

        // A workforce login never yields a code for a customer client: the browser is sent to the customer login.
        String person = principal(t.id, t.s + "-pat", null);
        MvcResult workforceAtCustomer = authorize(customerClient, "openid " + READ, challenge("v".repeat(50)), "s1", null,
                user(person));
        assertThat(workforceAtCustomer.getResponse().getStatus()).isEqualTo(302);
        assertThat(workforceAtCustomer.getResponse().getHeader(HttpHeaders.LOCATION)).endsWith("/login/customer")
                .doesNotContain("code=");

        // The customer's login cannot obtain a code for a workforce client: it is cleared and sent to /login.
        String workforceClient = browserClient(t, appId, t.s + "-staff-web", List.of(READ));
        MvcResult customerAtWorkforce = authorize(workforceClient, "openid " + READ, challenge("w".repeat(50)), "s2",
                login.session(), null);
        assertThat(customerAtWorkforce.getResponse().getStatus()).isEqualTo(302);
        assertThat(customerAtWorkforce.getResponse().getHeader(HttpHeaders.LOCATION)).endsWith("/login")
                .doesNotContain("code=");

        // Workforce credentials are refused on the customer form; customer credentials on the workforce form.
        MockHttpSession wrong = new MockHttpSession();
        authorize(customerClient, "openid", challenge("x".repeat(50)), "s3", wrong, null);
        MvcResult refused = mvc.perform(post("/login/customer").session(wrong).with(csrf())
                .param("username", person).param("password", PASSWORD)).andReturn();
        assertThat(refused.getResponse().getHeader(HttpHeaders.LOCATION)).endsWith("/login/customer?error");

        // Suspension stops the customer's tokens (online) and any further sign-in.
        body(send(post(base(t) + "/ciam/customers/" + c.id() + "/suspend"), t.admin, null), 200);
        assertThat(introspect(introspector(t), tokens.get("access_token").asText()).path("active").asBoolean()).isFalse();
        MockHttpSession after = new MockHttpSession();
        authorize(customerClient, "openid", challenge("y".repeat(50)), "s4", after, null);
        MvcResult suspended = mvc.perform(post("/login/customer").session(after).with(csrf())
                .param("username", c.email()).param("password", PASSWORD)).andReturn();
        assertThat(suspended.getResponse().getHeader(HttpHeaders.LOCATION)).endsWith("/login/customer?error");
    }

    @Test
    void customerLoginRequiresAPendingAuthorizationRequestAndCsrf() throws Exception {
        Tenant t = tenant("idp-a");
        Customer c = activeCustomer(t, "dora");
        MvcResult noRequest = mvc.perform(post("/login/customer").session(new MockHttpSession()).with(csrf())
                .param("username", c.email()).param("password", PASSWORD)).andReturn();
        assertThat(noRequest.getResponse().getHeader(HttpHeaders.LOCATION)).endsWith("/login/customer?error");
        MvcResult noCsrf = mvc.perform(post("/login/customer").session(new MockHttpSession())
                .param("username", c.email()).param("password", PASSWORD)).andReturn();
        assertThat(noCsrf.getResponse().getStatus()).isEqualTo(403);
    }

    // -------------------------------------------------------------------------------------------------- refresh

    @Test
    void refreshTokensRotateAreClientBoundAndReuseWithdrawsTheFamily() throws Exception {
        Tenant t = tenant("idp-a");
        String audience = "bff:" + t.id + ":" + t.s;
        String appId = app(t, "bff", audience);
        Web web = webClient(t, appId, t.s + "-bff", "WORKFORCE", List.of("openid", "offline_access", READ), Map.of());
        Web other = webClient(t, appId, t.s + "-bff2", "WORKFORCE", List.of("openid", "offline_access", READ), Map.of());
        String person = principal(t.id, t.s + "-rui", null);
        entitle(t, appId, person, List.of(READ));

        JsonNode noOffline = tokenResponse(redeemConfidential(web, workforceCode(web.clientId(), person, "openid " + READ)));
        assertThat(noOffline.has("refresh_token")).as("no offline_access, no refresh token").isFalse();

        JsonNode first = tokenResponse(redeemConfidential(web,
                workforceCode(web.clientId(), person, "openid offline_access " + READ)));
        String r1 = first.get("refresh_token").asText();
        assertThat(r1).isNotBlank();
        // Token types are not interchangeable: a live access or ID token is never renewal input, and presenting one
        // does not disturb the family.
        denied(refresh(web, first.get("access_token").asText()), "invalid_grant");
        denied(refresh(web, first.get("id_token").asText()), "invalid_grant");
        denied(refresh(other, r1), "invalid_grant");
        JsonNode second = tokenResponse(refresh(web, r1));
        String r2 = second.get("refresh_token").asText();
        assertThat(r2).as("rotated").isNotEqualTo(r1);
        assertThat(claims(second.get("access_token").asText()).get("sub")).isEqualTo(person);
        assertThat(introspect(introspector(t), second.get("access_token").asText()).path("active").asBoolean()).isTrue();

        // Reuse of the spent token withdraws the whole family: the current refresh token and access token stop too.
        denied(refresh(web, r1), "invalid_grant");
        denied(refresh(web, r2), "invalid_grant");
        assertThat(introspect(introspector(t), second.get("access_token").asText()).path("active").asBoolean()).isFalse();

        // Withdrawn authority: disabling the person stops renewal of an independent family.
        JsonNode third = tokenResponse(redeemConfidential(web,
                workforceCode(web.clientId(), person, "openid offline_access " + READ)));
        jdbc.update("UPDATE principals SET is_active = FALSE WHERE id = ?", person);
        denied(refresh(web, third.get("refresh_token").asText()), "invalid_grant");

        // An access token is not renewal input.
        denied(refresh(web, second.get("access_token").asText()), "invalid_grant");
        // Public browser clients never receive refresh tokens.
        String publicClient = browserClient(t, appId, t.s + "-spa", List.of(READ));
        assertThat(body(send(get(base(t) + "/applications/" + appId + "/clients"), t.admin, null), 200).toString())
                .contains(publicClient);
    }

    // ------------------------------------------------------------------------------- scope versus entitlement

    @Test
    void aBusinessScopeIsIssuedOnlyWhenThePersonHoldsThatPermission() throws Exception {
        Tenant t = tenant("idp-a");
        String audience = "ent:" + t.id + ":" + t.s;
        String appId = app(t, "ent", audience);
        String client = interactiveClient(t, appId, t.s + "-ent-web", "PUBLIC_BROWSER", "WORKFORCE",
                List.of("openid", READ, WRITE), Map.of());
        String person = principal(t.id, t.s + "-una", null);
        entitle(t, appId, person, List.of(READ));
        Login login = workforceCode(client, person, "openid " + READ + " " + WRITE);
        JsonNode tokens = tokenResponse(redeemPublic(client, login));
        String scope = String.valueOf(claims(tokens.get("access_token").asText()).get("scope"));
        assertThat(scope).contains(READ).doesNotContain(WRITE);
        assertThat(tokens.path("scope").asText()).as("the token response reports the issued scope")
                .contains(READ).doesNotContain(WRITE);
    }

    // ------------------------------------------------------------------------------------------ OAuth consent

    @Test
    void aConsentRequiringCustomerClientShowsTheConsentPageAndIssuesOnlyApprovedScopes() throws Exception {
        Tenant t = tenant("idp-a");
        String audience = "consent:" + t.id + ":" + t.s;
        String appId = app(t, "consent", audience);
        String client = interactiveClient(t, appId, t.s + "-consent-web", "PUBLIC_BROWSER", "CUSTOMER",
                List.of("openid", READ, WRITE), Map.of("requireConsent", true));
        Customer c = activeCustomer(t, "faye");
        MockHttpSession session = new MockHttpSession();
        String verifier = Base64.getUrlEncoder().withoutPadding().encodeToString(randomBytes(48));
        authorize(client, "openid " + READ + " " + WRITE, challenge(verifier), "c1", session, null);
        mvc.perform(post("/login/customer").session(session).with(csrf())
                .param("username", c.email()).param("password", PASSWORD)).andReturn();
        MvcResult authorized = authorize(client, "openid " + READ + " " + WRITE, challenge(verifier), "c1", session, null);
        // The authorization endpoint sends the browser to Axiom's own consent page.
        assertThat(authorized.getResponse().getStatus()).isEqualTo(302);
        assertThat(authorized.getResponse().getHeader(HttpHeaders.LOCATION)).contains("/oauth2/consent");
        MvcResult page = mvc.perform(get(URI.create(authorized.getResponse().getHeader(HttpHeaders.LOCATION)))
                .session(session)).andReturn();
        String html = page.getResponse().getContentAsString();
        assertThat(page.getResponse().getStatus()).isEqualTo(200);
        assertThat(html).contains("consent_form").contains("value=\"" + READ + "\"").contains("value=\"" + WRITE + "\"");
        String consentState = html.replaceAll("(?s).*name=\"state\" value=\"([^\"]+)\".*", "$1");
        MvcResult consented = mvc.perform(post("/oauth/authorize").session(session)
                .param("client_id", client).param("state", consentState).param("scope", READ)).andReturn();
        String location = consented.getResponse().getHeader(HttpHeaders.LOCATION);
        assertThat(location).as("consent submission redirects with a code").startsWith(CALLBACK).contains("code=");
        String code = UriComponentsBuilder.fromUriString(location).build().getQueryParams().getFirst("code");
        JsonNode tokens = tokenResponse(redeemPublic(client, new Login(session, code, verifier, "c1")));
        String scope = String.valueOf(claims(tokens.get("access_token").asText()).get("scope"));
        assertThat(scope).contains(READ).doesNotContain(WRITE);
    }

    // --------------------------------------------------------------------------------------------- logout

    @Test
    void rpInitiatedLogoutByFormPostFromARelyingPartyOriginIsNotRefusedByCors() throws Exception {
        Tenant t = tenant("idp-a");
        String person = principal(t.id, t.s + "-lou", null);
        CodeLogin login = pkce("axiom-admin", "http://localhost:5180/callback", person, "openid");
        MvcResult logout = mvc.perform(post("/connect/logout").contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .header(HttpHeaders.ORIGIN, "https://relying-party.example")
                .param("id_token_hint", login.idToken())
                .param("post_logout_redirect_uri", "http://localhost:5180/login")).andReturn();
        assertThat(logout.getResponse().getStatus()).as("a cross-origin form POST is a navigation, not CORS")
                .isEqualTo(302);
        assertThat(logout.getResponse().getHeader(HttpHeaders.LOCATION)).isEqualTo("http://localhost:5180/login");
        assertThat(send(get("/api/me/sessions"), login.accessToken(), null).getResponse().getStatus()).isEqualTo(401);
        MvcResult unregistered = mvc.perform(post("/connect/logout").contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .header(HttpHeaders.ORIGIN, "https://relying-party.example")
                .param("id_token_hint", pkce("axiom-admin", "http://localhost:5180/callback", person, "openid").idToken())
                .param("post_logout_redirect_uri", "https://evil.example/after")).andReturn();
        assertThat(unregistered.getResponse().getHeader(HttpHeaders.LOCATION)).as("unregistered post-logout URI")
                .isNotEqualTo("https://evil.example/after");
    }

    // --------------------------------------------------------------------------- metadata, UserInfo, own assets

    @Test
    void discoveryNamesTheEnabledScopesAndUserInfoServesBothPopulations() throws Exception {
        JsonNode meta = json.readTree(mvc.perform(get("/.well-known/openid-configuration")).andReturn().getResponse()
                .getContentAsString());
        List<String> scopes = json.convertValue(meta.path("scopes_supported"), List.class);
        assertThat(scopes).contains("openid", "profile", "email", "offline_access", READ, WRITE);

        Tenant t = tenant("idp-a");
        String audience = "ui:" + t.id + ":" + t.s;
        String appId = app(t, "ui", audience);
        String staff = interactiveClient(t, appId, t.s + "-ui-web", "PUBLIC_BROWSER", "WORKFORCE",
                List.of("openid", "email", READ), Map.of());
        String shop = interactiveClient(t, appId, t.s + "-ui-shop", "PUBLIC_BROWSER", "CUSTOMER",
                List.of("openid", "email", READ), Map.of());
        String person = principal(t.id, t.s + "-uma", null);
        entitle(t, appId, person, List.of(READ));
        CodeLogin workforceLogin = pkce(staff, CALLBACK, person, "openid email");
        String workforce = workforceLogin.accessToken();
        JsonNode wf = body(send(get("/oauth/userinfo"), workforce, null), 200);
        assertThat(wf.path("sub").asText()).isEqualTo(person);
        assertThat(send(get("/oauth/userinfo"), workforceLogin.idToken(), null).getResponse().getStatus())
                .as("an ID token is not a UserInfo bearer access token").isIn(401, 403);
        Customer c = activeCustomer(t, "uri");
        String customer = tokenResponse(redeemPublic(shop, customerLogin(shop, c, "openid email")))
                .get("access_token").asText();
        JsonNode cu = body(send(get("/oauth/userinfo"), customer, null), 200);
        assertThat(cu.path("sub").asText()).isEqualTo(c.id());
        assertThat(cu.path("email").asText()).isEqualTo(c.email());
        Svc software = introspector(t);
        String softwareToken = clientCredentials(software, READ);
        assertThat(send(get("/oauth/userinfo"), softwareToken, null).getResponse().getStatus())
                .as("a software token has no user to describe").isIn(401, 403);
    }

    @Test
    void loginAndConsentPagesLoadNoThirdPartyAssets() throws Exception {
        Tenant t = tenant("idp-a");
        String appId = app(t, "assets", "assets:" + t.id + ":" + t.s);
        String client = interactiveClient(t, appId, t.s + "-assets-web", "PUBLIC_BROWSER", "CUSTOMER",
                List.of("openid", READ), Map.of("requireConsent", true));
        Customer c = activeCustomer(t, "asa");
        for (String path : List.of("/login", "/login/customer")) {
            String html = mvc.perform(get(path)).andReturn().getResponse().getContentAsString();
            assertThat(html).as(path).doesNotContainPattern("(?i)(href|src)=\"(https?:)?//");
        }
        MockHttpSession session = new MockHttpSession();
        String verifier = Base64.getUrlEncoder().withoutPadding().encodeToString(randomBytes(48));
        authorize(client, "openid " + READ, challenge(verifier), "a1", session, null);
        mvc.perform(post("/login/customer").session(session).with(csrf())
                .param("username", c.email()).param("password", PASSWORD)).andReturn();
        MvcResult page = authorize(client, "openid " + READ, challenge(verifier), "a1", session, null);
        String consent = page.getResponse().getStatus() == 302
                ? mvc.perform(get(URI.create(page.getResponse().getHeader(HttpHeaders.LOCATION))).session(session))
                        .andReturn().getResponse().getContentAsString()
                : page.getResponse().getContentAsString();
        assertThat(consent).contains("consent_form").doesNotContainPattern("(?i)(href|src)=\"(https?:)?//");
    }

    // ---------------------------------------------------------------------------------------- private_key_jwt

    @Test
    void privateKeyJwtAuthenticatesAWorkloadWithSingleUseAssertions() throws Exception {
        Tenant t = tenant("idp-a");
        String audience = "jobs:" + t.id + ":" + t.s;
        String appId = app(t, "jobs", audience);
        RSAKey key = new RSAKeyGenerator(2048).keyID("k1").generate();
        RSAKey stranger = new RSAKeyGenerator(2048).keyID("k1").generate();
        String clientId = t.s + "-jwt";
        JsonNode created = body(send(post(base(t) + "/applications/" + appId + "/clients"), t.admin, Map.of(
                "clientId", clientId, "clientType", "CONFIDENTIAL_SERVICE", "redirectUris", List.of(),
                "postLogoutRedirectUris", List.of(), "scopes", List.of(READ), "tokenEndpointAuthMethod", "private_key_jwt",
                "jwks", Map.of("keys", List.of(key.toPublicJWK().toJSONObject())))), 201);
        assertThat(created.path("serviceSecret").isNull() || created.path("serviceSecret").isMissingNode()).isTrue();
        assertThat(created.path("client").path("tokenEndpointAuthMethods").toString()).contains("private_key_jwt");
        assertThat(created.path("client").path("publicKeyIds").toString()).contains("k1");

        // A private key in the registration is refused.
        MvcResult privateKey = send(post(base(t) + "/applications/" + appId + "/clients"), t.admin, Map.of(
                "clientId", t.s + "-jwt2", "clientType", "CONFIDENTIAL_SERVICE", "scopes", List.of(READ),
                "tokenEndpointAuthMethod", "private_key_jwt", "jwks", Map.of("keys", List.of(key.toJSONObject()))));
        assertThat(privateKey.getResponse().getStatus()).isEqualTo(400);

        String tokenEndpoint = issuer() + "/oauth/token";
        String assertion = assertion(key, clientId, tokenEndpoint, 60, UUID.randomUUID().toString());
        MvcResult ok = clientAssertion(clientId, assertion, READ);
        Map<String, Object> claims = claims(tokenResponse(ok).get("access_token").asText());
        assertThat(claims.get("sub")).isEqualTo(clientId);
        assertThat(audiences(claims)).isEqualTo(List.of(audience));
        assertThat(clientAssertion(clientId, assertion, READ).getResponse().getStatus()).as("replay").isEqualTo(401);
        assertThat(clientAssertion(clientId, assertion(stranger, clientId, tokenEndpoint, 60, UUID.randomUUID().toString()),
                READ).getResponse().getStatus()).as("wrong key").isEqualTo(401);
        assertThat(clientAssertion(clientId, assertion(key, clientId, "https://elsewhere.invalid/token", 60,
                UUID.randomUUID().toString()), READ).getResponse().getStatus()).as("wrong audience").isEqualTo(401);
        assertThat(clientAssertion(clientId, assertion(key, clientId, tokenEndpoint, -30, UUID.randomUUID().toString()),
                READ).getResponse().getStatus()).as("expired").isEqualTo(401);
        assertThat(clientAssertion(clientId, assertion(key, clientId, tokenEndpoint, 3600, UUID.randomUUID().toString()),
                READ).getResponse().getStatus()).as("lifetime above five minutes").isEqualTo(401);
        assertThat(clientAssertion(clientId, assertion(key, clientId, tokenEndpoint, 60, null), READ)
                .getResponse().getStatus()).as("no jti").isEqualTo(401);
        String rowId = created.path("client").path("id").asText();
        body(send(org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete(
                base(t) + "/applications/" + appId + "/clients/" + rowId), t.admin, null), 204);
        assertThat(clientAssertion(clientId, assertion(key, clientId, tokenEndpoint, 60, UUID.randomUUID().toString()),
                READ).getResponse().getStatus()).as("disabled client").isEqualTo(401);
    }

    // --------------------------------------------------------------------------------------- lifetime policy

    @Test
    void interactiveAccessTokenLifetimeIsConfigurablePerClientWithinTheCeiling() throws Exception {
        Tenant t = tenant("idp-a");
        String appId = app(t, "ttl", "ttl:" + t.id + ":" + t.s);
        String client = interactiveClient(t, appId, t.s + "-ttl-web", "PUBLIC_BROWSER", "WORKFORCE",
                List.of("openid", READ), Map.of("accessTokenTtlSeconds", 300));
        String person = principal(t.id, t.s + "-tia", null);
        entitle(t, appId, person, List.of(READ));
        Map<String, Object> claims = claims(pkce(client, CALLBACK, person, "openid " + READ).accessToken());
        assertThat(((Number) claims.get("exp")).longValue() - ((Number) claims.get("iat")).longValue()).isEqualTo(300);
        MvcResult tooLong = send(post(base(t) + "/applications/" + appId + "/clients"), t.admin, Map.of(
                "clientId", t.s + "-ttl2", "clientType", "PUBLIC_BROWSER", "redirectUris", List.of(CALLBACK),
                "scopes", List.of("openid"), "accessTokenTtlSeconds", 7200));
        assertThat(tooLong.getResponse().getStatus()).isEqualTo(400);
        MvcResult serviceTtl = send(post(base(t) + "/applications/" + appId + "/clients"), t.admin, Map.of(
                "clientId", t.s + "-ttl3", "clientType", "CONFIDENTIAL_SERVICE", "scopes", List.of(READ),
                "accessTokenTtlSeconds", 300));
        assertThat(serviceTtl.getResponse().getStatus()).as("service clients use the client-credentials TTL").isEqualTo(400);
    }

    // ---------------------------------------------------------------------- customer-preserving continuation

    @Test
    void customerAuthorityContinuesAlongExplicitEdgesAndStopsWhenTheCustomerIsSuspended() throws Exception {
        Tenant t = tenant("idp-a");
        Svc shopSvc = workload(t, "shopsvc", List.of(READ));
        String customerClient = interactiveClient(t, shopSvc.appId(), t.s + "-shop-spa", "PUBLIC_BROWSER", "CUSTOMER",
                List.of("openid", READ), Map.of());
        String edgeAudience = "edge:" + t.id + ":" + t.s;
        Svc edge = confidential(t, app(t, "edge", edgeAudience), edgeAudience, t.s + "-edge", List.of(READ));
        body(send(post(base(t) + "/agent-exchange/brokers"), t.admin, Map.of("oauthClientId", edge.clientId(),
                "gatewayAudience", edgeAudience, "scopes", List.of(READ))), 201);
        String resourceAudience = "orders:" + t.id + ":" + t.s;
        app(t, "orders", resourceAudience);
        route(t, shopSvc.workloadId(), "GATEWAY", null, edgeAudience, List.of(READ));
        route(t, shopSvc.workloadId(), "RESOURCE", null, resourceAudience, List.of(READ));
        Customer c = activeCustomer(t, "erin");
        String customerToken = tokenResponse(redeemPublic(customerClient,
                customerLogin(customerClient, c, "openid " + READ))).get("access_token").asText();

        String hop1 = token(exchange(shopSvc, customerToken, shopSvc.audience(), READ, Map.of()));
        Map<String, Object> h1 = claims(hop1);
        assertThat(h1.get("sub")).isEqualTo(c.id());
        assertThat(h1.get("client_id")).isEqualTo(shopSvc.clientId());
        assertThat(((Map<?, ?>) h1.get("act")).get("client_id")).isEqualTo(shopSvc.clientId());
        String hop2 = token(exchange(shopSvc, hop1, edgeAudience, READ, Map.of()));
        String hop3 = token(exchange(edge, hop2, resourceAudience, READ, Map.of()));
        Map<String, Object> h3 = claims(hop3);
        assertThat(h3.get("sub")).as("the customer stays the subject").isEqualTo(c.id());
        assertThat(audiences(h3)).isEqualTo(List.of(resourceAudience));
        assertThat(((Map<?, ?>) h3.get("act")).get("client_id")).as("the intermediary never becomes the actor")
                .isEqualTo(shopSvc.clientId());
        assertThat(introspect(introspector(t), hop3).path("active").asBoolean()).isTrue();

        // Denials: a workload of another application, widening, an unregistered destination, onward from a resource.
        Svc stranger = workload(t, "stranger", List.of(READ, WRITE));
        denied(exchange(stranger, customerToken, stranger.audience(), READ, Map.of()), "invalid_grant");
        assertThat(exchange(shopSvc, customerToken, shopSvc.audience(), READ + " " + WRITE, Map.of())
                .getResponse().getStatus()).isIn(400, 401);
        assertThat(exchange(shopSvc, hop1, "unregistered:" + t.s, READ, Map.of()).getResponse().getStatus()).isIn(400, 401);
        assertThat(exchange(edge, hop3, resourceAudience, READ, Map.of()).getResponse().getStatus())
                .as("resource tokens are terminal").isIn(400, 401);

        body(send(post(base(t) + "/ciam/customers/" + c.id() + "/suspend"), t.admin, null), 200);
        assertThat(introspect(introspector(t), hop3).path("active").asBoolean()).as("suspension reaches the chain").isFalse();
        assertThat(exchange(shopSvc, customerToken, shopSvc.audience(), READ, Map.of()).getResponse().getStatus())
                .isIn(400, 401);
    }

    // =============================================================================================== helpers

    /** {@code aud} is a JSON string for one audience and an array for several (RFC 7519 section 4.1.3). */
    private static List<?> audiences(Map<String, Object> claims) {
        Object aud = claims.get("aud");
        return aud instanceof List<?> list ? list : List.of(aud);
    }

    /** A same-tenant confidential client used only to introspect (a generic resource server). */
    private Svc introspector(Tenant t) throws Exception {
        String suffix = UUID.randomUUID().toString().substring(0, 4);
        String aud = "rs:" + t.id + ":" + t.s + "-" + suffix;
        return confidential(t, app(t, "rs" + suffix, aud), aud, t.s + "-rs" + suffix, List.of(READ));
    }

    record Customer(String id, String email) {}
    record Login(MockHttpSession session, String code, String verifier, String state) {}
    record Web(String clientId, String secret) {}

    private Customer activeCustomer(Tenant t, String name) throws Exception {
        String email = t.s + "-" + name + "@customers.invalid";
        JsonNode created = body(send(post(base(t) + "/ciam/customers"), t.admin, Map.of("email", email,
                "displayName", name, "initialPassword", PASSWORD)), 201);
        String id = created.get("customerId").asText();
        // Java-only fixture: the verification delivery path is exercised by the customer-code ITs and the Python suite.
        jdbc.update("UPDATE customer_identities SET status = 'ACTIVE', email_verified_at = now() WHERE id = ?::uuid", id);
        return new Customer(id, email);
    }

    private String interactiveClient(Tenant t, String appId, String clientId, String type, String population,
                                     List<String> scopes, Map<String, Object> extra) throws Exception {
        Map<String, Object> request = new HashMap<>(Map.of("clientId", clientId, "clientType", type,
                "population", population, "redirectUris", List.of(CALLBACK), "postLogoutRedirectUris", List.of(),
                "scopes", scopes));
        request.putAll(extra);
        body(send(post(base(t) + "/applications/" + appId + "/clients"), t.admin, request), 201);
        return clientId;
    }

    private Web webClient(Tenant t, String appId, String clientId, String population, List<String> scopes,
                          Map<String, Object> extra) throws Exception {
        Map<String, Object> request = new HashMap<>(Map.of("clientId", clientId, "clientType", "CONFIDENTIAL_WEB",
                "population", population, "redirectUris", List.of(CALLBACK), "postLogoutRedirectUris", List.of(),
                "scopes", scopes));
        request.putAll(extra);
        JsonNode created = body(send(post(base(t) + "/applications/" + appId + "/clients"), t.admin, request), 201);
        assertThat(created.path("client").path("grantTypes").toString()).contains("refresh_token");
        return new Web(clientId, created.get("serviceSecret").asText());
    }

    private static String challenge(String verifier) throws Exception {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(
                MessageDigest.getInstance("SHA-256").digest(verifier.getBytes(StandardCharsets.US_ASCII)));
    }

    private MvcResult authorize(String clientId, String scope, String challenge, String state, MockHttpSession session,
                                org.springframework.test.web.servlet.request.RequestPostProcessor auth) throws Exception {
        var request = get("/oauth/authorize").queryParam("response_type", "code").queryParam("client_id", clientId)
                .queryParam("redirect_uri", CALLBACK).queryParam("scope", scope).queryParam("state", state)
                .queryParam("nonce", "n-" + state).queryParam("code_challenge", challenge)
                .queryParam("code_challenge_method", "S256").accept(MediaType.TEXT_HTML);
        if (session != null) request = request.session(session);
        if (auth != null) request = request.with(auth);
        return mvc.perform(request).andReturn();
    }

    /** The customer browser ceremony: authorize → customer login page → form (CSRF) → resumed authorize → code. */
    private Login customerLogin(String clientId, Customer c, String scope) throws Exception {
        MockHttpSession session = new MockHttpSession();
        String verifier = Base64.getUrlEncoder().withoutPadding().encodeToString(randomBytes(48));
        String state = UUID.randomUUID().toString().substring(0, 8);
        MvcResult first = authorize(clientId, scope, challenge(verifier), state, session, null);
        assertThat(first.getResponse().getStatus()).isEqualTo(302);
        assertThat(first.getResponse().getHeader(HttpHeaders.LOCATION)).endsWith("/login/customer");
        assertThat(mvc.perform(get("/login/customer").session(session)).andReturn().getResponse().getStatus()).isEqualTo(200);
        MvcResult form = mvc.perform(post("/login/customer").session(session).with(csrf())
                .param("username", c.email()).param("password", PASSWORD)).andReturn();
        assertThat(form.getResponse().getStatus()).isEqualTo(302);
        String resume = form.getResponse().getHeader(HttpHeaders.LOCATION);
        assertThat(resume).contains("/oauth/authorize");
        MvcResult resumed = mvc.perform(get(URI.create(resume)).session(session).accept(MediaType.TEXT_HTML)).andReturn();
        String location = resumed.getResponse().getHeader(HttpHeaders.LOCATION);
        assertThat(location).as("code callback").startsWith(CALLBACK);
        var params = UriComponentsBuilder.fromUriString(location).build().getQueryParams();
        assertThat(params.getFirst("state")).isEqualTo(state);
        return new Login(session, params.getFirst("code"), verifier, state);
    }

    private Login workforceCode(String clientId, String person, String scope) throws Exception {
        String verifier = Base64.getUrlEncoder().withoutPadding().encodeToString(randomBytes(48));
        MvcResult r = authorize(clientId, scope, challenge(verifier), "wf", null, user(person));
        String location = r.getResponse().getHeader(HttpHeaders.LOCATION);
        assertThat(location).startsWith(CALLBACK);
        return new Login(null, UriComponentsBuilder.fromUriString(location).build().getQueryParams().getFirst("code"),
                verifier, "wf");
    }

    private MvcResult redeemPublic(String clientId, Login login) throws Exception {
        return mvc.perform(post("/oauth/token").contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .param("grant_type", "authorization_code").param("client_id", clientId).param("code", login.code())
                .param("redirect_uri", CALLBACK).param("code_verifier", login.verifier())).andReturn();
    }

    private MvcResult redeemConfidential(Web web, Login login) throws Exception {
        return mvc.perform(post("/oauth/token").contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .header(HttpHeaders.AUTHORIZATION, basic(web)).param("grant_type", "authorization_code")
                .param("code", login.code()).param("redirect_uri", CALLBACK).param("code_verifier", login.verifier()))
                .andReturn();
    }

    private MvcResult refresh(Web web, String refreshToken) throws Exception {
        return mvc.perform(post("/oauth/token").contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .header(HttpHeaders.AUTHORIZATION, basic(web)).param("grant_type", "refresh_token")
                .param("refresh_token", refreshToken)).andReturn();
    }

    private static String basic(Web web) {
        return "Basic " + Base64.getEncoder().encodeToString((web.clientId() + ":" + web.secret())
                .getBytes(StandardCharsets.UTF_8));
    }

    private String issuer() throws Exception {
        return json.readTree(mvc.perform(get("/.well-known/oauth-authorization-server")).andReturn().getResponse()
                .getContentAsString()).get("issuer").asText();
    }

    private static String assertion(RSAKey key, String clientId, String audience, long seconds, String jti)
            throws Exception {
        Instant now = Instant.now();
        JWTClaimsSet.Builder claims = new JWTClaimsSet.Builder().issuer(clientId).subject(clientId).audience(audience)
                .issueTime(Date.from(now)).expirationTime(Date.from(now.plusSeconds(seconds)));
        if (jti != null) claims.jwtID(jti);
        SignedJWT jwt = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(key.getKeyID())
                .type(JOSEObjectType.JWT).build(), claims.build());
        jwt.sign(new RSASSASigner(key));
        return jwt.serialize();
    }

    private MvcResult clientAssertion(String clientId, String assertion, String scope) throws Exception {
        return mvc.perform(post("/oauth/token").contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .param("grant_type", "client_credentials").param("scope", scope).param("client_id", clientId)
                .param("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
                .param("client_assertion", assertion)).andReturn();
    }
}
