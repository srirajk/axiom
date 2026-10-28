package com.openwolf.iam.authority.issuer;

import com.fasterxml.jackson.databind.JsonNode;
import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.*;
import com.openwolf.iam.IamApplication;
import com.openwolf.iam.auth.CimdHttpFetcher;
import com.openwolf.iam.authority.AuthorityITSupport;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.*;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.web.util.UriComponentsBuilder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.*;
import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.*;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;

/** Real PostgreSQL/Redis, Spring's code/consent/token flows; only outbound CIMD/JWKS HTTP is stubbed. */
@SpringBootTest(classes=IamApplication.class, webEnvironment=SpringBootTest.WebEnvironment.MOCK)
@AutoConfigureMockMvc
class McpClientSupportIT extends AuthorityITSupport {
    static final String CALLBACK = "http://127.0.0.1:51234/callback";
    static final String VERIFIER = "m".repeat(64);
    @MockitoBean CimdHttpFetcher fetcher;
    @org.springframework.beans.factory.annotation.Autowired com.openwolf.iam.auth.CimdDocuments documents;
    @org.springframework.beans.factory.annotation.Autowired com.openwolf.iam.auth.CimdRegisteredClientRepository registrations;
    @org.springframework.beans.factory.annotation.Autowired com.openwolf.iam.service.CustomerOAuthConsentService customerConsents;
    @org.springframework.beans.factory.annotation.Autowired com.openwolf.iam.service.TenantApplicationService applications;
    @org.springframework.beans.factory.annotation.Autowired org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService authorizations;
    record Fixture(Tenant tenant, String app, String audience, String person) {}
    record Code(String client, String code, String redirect, MockHttpSession session) {}

    Fixture fixture(String tenantId) throws Exception {
        Tenant t = tenant(tenantId);
        String audience = "https://mcp.example/" + t.id + "/" + t.s;
        String app = app(t, "mcp", audience);
        String person = principal(t.id, t.s + "-person", null);
        entitle(t, app, person, List.of(READ));
        return new Fixture(t, app, audience, person);
    }
    String staticClient(Fixture f, boolean refresh) throws Exception {
        String id = f.tenant.s + "-public-" + UUID.randomUUID().toString().substring(0,6);
        Map<String,Object> body = new HashMap<>(Map.of("clientId",id,"clientType","PUBLIC_BROWSER",
                "redirectUris",List.of("http://127.0.0.1/callback", "http://localhost/callback", "http://[::1]/callback"),
                "scopes", refresh ? List.of("openid",READ,"offline_access") : List.of("openid",READ), "refreshTokens",refresh));
        body(send(post(base(f.tenant)+"/applications/"+f.app+"/clients"), f.tenant.admin, body),201);
        return id;
    }
    String url() { return "https://ai.example/clients/"+UUID.randomUUID()+".json"; }
    JsonNode trust(Fixture f,String id,String method,List<String> redirects) throws Exception {
        return body(send(post(base(f.tenant)+"/applications/"+f.app+"/trusted-clients"),f.tenant.admin,
                Map.of("clientId",id,"redirectUris",redirects,"tokenEndpointAuthMethod",method,
                        "scopes",List.of("openid",READ),"refreshTokens",true)),201);
    }
    Map<String,Object> document(String id,String method,List<String> redirects) {
        return new HashMap<>(Map.of("client_id",id,"client_name","Example AI","redirect_uris",redirects,
                "grant_types",List.of("authorization_code","refresh_token"),"token_endpoint_auth_method",method));
    }
    void serve(String url,Map<String,Object> document) throws Exception {
        when(fetcher.fetch(url)).thenReturn(new CimdHttpFetcher.Response(json.writeValueAsBytes(document),"max-age=3600",0));
    }
    MvcResult authorization(Fixture f,String client,String redirect,String scope,String resource,String challenge,String method,
                             MockHttpSession session) throws Exception {
        var request=get("/oauth/authorize").with(user(f.person)).session(session).queryParam("client_id",client)
                .queryParam("response_type","code").queryParam("redirect_uri",redirect).queryParam("scope",scope).queryParam("state","client-state")
                .queryParam("code_challenge",challenge).queryParam("code_challenge_method",method);
        if(resource!=null)request.queryParam("resource",resource);
        return mvc.perform(request).andReturn();
    }
    Code code(Fixture f,String client,String redirect,boolean offline) throws Exception {
        MockHttpSession session=new MockHttpSession();
        MvcResult result=authorization(f,client,redirect,"openid "+READ+(offline?" offline_access":""),f.audience,
                challenge(),"S256",session);
        String location=result.getResponse().getHeader("Location");
        assertThat(result.getResponse().getStatus()).isEqualTo(302);
        if (client.startsWith("https://")) assertThat(location).contains("/oauth2/consent");
        if(location.contains("/oauth2/consent")) {
            String state=query(location,"state");
            MvcResult page=mvc.perform(get("/oauth2/consent").with(user(f.person)).session(session)
                    .param("client_id",client).param("state",state).param("scope",READ+" offline_access")).andReturn();
            assertThat(page.getResponse().getStatus()).isEqualTo(200);
            assertThat(page.getResponse().getContentAsString()).contains("ai.example", java.net.URI.create(redirect).getHost());
            if(redirect.startsWith("http://"))assertThat(page.getResponse().getContentAsString()).contains("on your device");
            result=mvc.perform(post("/oauth/authorize").with(user(f.person)).session(session).param("client_id",client)
                    .param("state",state).param("scope",offline?new String[]{READ,"offline_access"}:new String[]{READ})).andReturn();
            location=result.getResponse().getHeader("Location");
        }
        assertThat(location).startsWith(redirect).contains("code=","iss=");
        return new Code(client,query(location,"code"),redirect,session);
    }
    MvcResult redeem(Code code,String assertion,String verifier) throws Exception {
        var request=post("/oauth/token").contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .param("client_id",code.client).param("grant_type","authorization_code").param("code",code.code)
                .param("redirect_uri",code.redirect).param("code_verifier",verifier);
        if(assertion!=null)request.param("client_assertion_type","urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
                .param("client_assertion",assertion);
        return mvc.perform(request).andReturn();
    }
    JsonNode tokens(Code code) throws Exception { return body(redeem(code,null,VERIFIER),200); }
    MvcResult refresh(String client,String token) throws Exception {
        return mvc.perform(post("/oauth/token").contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .param("grant_type","refresh_token").param("client_id",client).param("refresh_token",token)).andReturn();
    }
    static String query(String location,String key) {
        String raw=UriComponentsBuilder.fromUriString(location).build().getQueryParams().getFirst(key);
        return raw==null?null:org.springframework.web.util.UriUtils.decode(raw,StandardCharsets.UTF_8);
    }
    static String challenge() throws Exception {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(MessageDigest.getInstance("SHA-256").digest(VERIFIER.getBytes(StandardCharsets.US_ASCII)));
    }

    @Test void group1PublicRefreshRotatesAndReplayWithdrawsTheFamilyAndSession() throws Exception {
        Fixture f=fixture("mcp-a");String client=staticClient(f,true);
        JsonNode first=tokens(code(f,client,CALLBACK,true));
        String r1=first.path("refresh_token").asText();assertThat(r1).isNotBlank();
        JsonNode second=body(refresh(client,r1),200);String r2=second.path("refresh_token").asText();
        assertThat(r2).isNotBlank().isNotEqualTo(r1);
        denied(refresh(client,r1),"invalid_grant");denied(refresh(client,r2),"invalid_grant");
        String sid=String.valueOf(claims(second.path("access_token").asText()).get("sid"));
        assertThat(jdbc.queryForObject("select status from iam_sessions where id=?::uuid",String.class,sid)).isEqualTo("REVOKED");
        assertThat(jdbc.queryForObject("select count(*) from audit_log where tenant_id=? and action='REFRESH_FAMILY_WITHDRAWN'",Integer.class,f.tenant.id)).isPositive();
        assertThat(tokens(code(f,client,CALLBACK,false)).has("refresh_token")).isFalse();
    }
    @Test void group2PublicRefreshDefaultStaysClosed() throws Exception {
        Fixture f=fixture("mcp-a");String client=staticClient(f,false);
        MvcResult result=authorization(f,client,CALLBACK,"openid "+READ+" offline_access",f.audience,challenge(),"S256",new MockHttpSession());
        assertThat(result.getResponse().getHeader("Location")).contains("error=invalid_scope","iss=");
        assertThat(tokens(code(f,client,CALLBACK,false)).has("refresh_token")).isFalse();
    }
    @Test void group3RefreshIsBoundToTheExactClient() throws Exception {
        Fixture f=fixture("mcp-a");String a=staticClient(f,true),b=staticClient(f,true);
        JsonNode issued=tokens(code(f,a,CALLBACK,true));
        denied(refresh(b,issued.path("refresh_token").asText()),"invalid_grant");
        JsonNode rotated=body(refresh(a,issued.path("refresh_token").asText()),200);
        denied(refresh(b,issued.path("refresh_token").asText()),"invalid_grant");
        body(refresh(a,rotated.path("refresh_token").asText()),200);
    }
    @Test void group4TrustedCimdSignsInAndUntrustedUrlNeverFetches() throws Exception {
        Fixture f=fixture("mcp-a");String id=url();trust(f,id,"none",List.of("http://127.0.0.1/callback"));
        serve(id,document(id,"none",List.of("http://127.0.0.1/callback")));
        JsonNode issued=tokens(code(f,id,CALLBACK,true));
        Map<String,Object> claims=claims(issued.path("access_token").asText());
        assertThat(claims).containsEntry("client_id",id).containsEntry("azp",id).containsEntry("tenant_id",f.tenant.id);
        assertThat(audiences(claims)).containsExactly(f.audience);
        JsonNode rotated=body(refresh(id,issued.path("refresh_token").asText()),200);
        denied(refresh(id,issued.path("refresh_token").asText()),"invalid_grant");
        denied(refresh(id,rotated.path("refresh_token").asText()),"invalid_grant");
        String unknown=url();denied(authorization(f,unknown,CALLBACK,"openid",f.audience,challenge(),"S256",new MockHttpSession()),"invalid_request");
        denied(refresh(unknown,"opaque-invalid-token"),"invalid_client");
        verify(fetcher,never()).fetch(unknown);
        assertThat(jdbc.queryForObject("select count(*) from audit_log where tenant_id=? and action='CIMD_SIGN_IN' and resource_id=?",Integer.class,f.tenant.id,id)).isPositive();
    }
    @Test void group5IdentityRedirectAndDocumentSizeCannotExpandApproval() throws Exception {
        Fixture f=fixture("mcp-a");
        String mismatch=url();trust(f,mismatch,"none",List.of("http://127.0.0.1/callback"));
        serve(mismatch,document(url(),"none",List.of("http://127.0.0.1/callback")));
        denied(authorization(f,mismatch,CALLBACK,"openid",f.audience,challenge(),"S256",new MockHttpSession()),"invalid_request");
        for(boolean inDocument:new boolean[]{true,false}) {
            String id=url();trust(f,id,"none",List.of(inDocument?"http://127.0.0.1/approved":"http://127.0.0.1/callback"));
            serve(id,document(id,"none",List.of(inDocument?"http://127.0.0.1/callback":"http://127.0.0.1/document-only")));
            MvcResult denied=authorization(f,id,CALLBACK,"openid",f.audience,challenge(),"S256",new MockHttpSession());
            assertThat(denied.getResponse().getStatus()).isEqualTo(400);assertThat(denied.getResponse().getHeader("Location")).isNull();
        }
        String huge=url();trust(f,huge,"none",List.of("http://127.0.0.1/callback"));
        when(fetcher.fetch(huge)).thenReturn(new CimdHttpFetcher.Response(new byte[65537],"max-age=3600",0));
        denied(authorization(f,huge,CALLBACK,"openid",f.audience,challenge(),"S256",new MockHttpSession()),"invalid_request");
    }
    @Test void group6SecondCimdSignInUsesTheValidatedCache() throws Exception {
        Fixture f=fixture("mcp-a");String id=url();trust(f,id,"none",List.of("http://127.0.0.1/callback"));
        serve(id,document(id,"none",List.of("http://127.0.0.1/callback")));
        tokens(code(f,id,CALLBACK,true));tokens(code(f,id,CALLBACK,true));
        verify(fetcher,times(1)).fetch(id);
    }
    @Test void group7CimdPrivateKeyJwtRequiresThePublishedKeyAndRejectsReplay() throws Exception {
        Fixture f=fixture("mcp-a");String id=url(),jwks=url();
        RSAKey key=new RSAKeyGenerator(2048).keyID("primary").generate();
        trust(f,id,"private_key_jwt",List.of("http://127.0.0.1/callback"));
        var doc=document(id,"private_key_jwt",List.of("http://127.0.0.1/callback"));doc.put("jwks_uri",jwks);serve(id,doc);
        serve(jwks,Map.of("keys",List.of(key.toPublicJWK().toJSONObject())));
        Code code=code(f,id,CALLBACK,true);
        String issuer=json.readTree(mvc.perform(get("/.well-known/oauth-authorization-server")).andReturn().getResponse().getContentAsString()).path("issuer").asText();
        RSAKey wrong=new RSAKeyGenerator(2048).keyID("primary").generate();
        denied(redeem(code,assertion(wrong,id,issuer,"wrong"),VERIFIER),"invalid_client");
        denied(redeem(code,null,VERIFIER),"invalid_client");
        denied(redeem(code,assertion(key,id,issuer,UUID.randomUUID().toString()),"wrong".repeat(16)),"invalid_grant");
        String assertion=assertion(key,id,issuer,UUID.randomUUID().toString());
        JsonNode issued=body(redeem(code,assertion,VERIFIER),200);assertThat(issued.has("refresh_token")).isTrue();
        denied(redeem(code(f,id,CALLBACK,true),assertion,VERIFIER),"invalid_client");
    }
    @Test void group8LoopbackPortsVaryButPathsHostsAndSchemesStayExact() throws Exception {
        Fixture f=fixture("mcp-a");String client=staticClient(f,true);
        for(String callback:List.of(CALLBACK,"http://localhost:51234/callback","http://[::1]:51234/callback")) tokens(code(f,client,callback,true));
        for(String callback:List.of("http://127.0.0.1:51234/other","https://127.0.0.1:51234/callback","http://localhost.evil:51234/callback","http://127.0.0.1:51234/%63allback")) {
            MvcResult result=authorization(f,client,callback,"openid",f.audience,challenge(),"S256",new MockHttpSession());
            assertThat(result.getResponse().getStatus()).isEqualTo(400);assertThat(result.getResponse().getHeader("Location")).isNull();
        }
    }
    @Test void group9IssuerAppearsOnSuccessAndValidatedErrorCallbacks() throws Exception {
        Fixture f=fixture("mcp-a");String client=staticClient(f,true);
        code(f,client,CALLBACK,true);
        String location=authorization(f,client,CALLBACK,"openid unapproved",f.audience,challenge(),"S256",new MockHttpSession())
                .getResponse().getHeader("Location");
        assertThat(location).contains("error=invalid_scope","iss=");
        assertThat(java.net.URLDecoder.decode(query(location,"iss"),StandardCharsets.UTF_8)).isEqualTo(discovery().path("issuer").asText());
        assertThat(discovery().path("authorization_response_iss_parameter_supported").asBoolean()).isTrue();
    }
    @Test void group10DiscoveryAdvertisesCimdAndNoneWithNoDynamicRegistration() throws Exception {
        for(String endpoint:List.of("/.well-known/oauth-authorization-server","/.well-known/openid-configuration")) {
            JsonNode metadata=json.readTree(mvc.perform(get(endpoint)).andReturn().getResponse().getContentAsString());
            assertThat(metadata.path("client_id_metadata_document_supported").asBoolean()).isTrue();
            assertThat(metadata.path("authorization_response_iss_parameter_supported").asBoolean()).isTrue();
            assertThat(metadata.path("token_endpoint_auth_methods_supported").toString()).contains("none","private_key_jwt");
            assertThat(metadata.has("registration_endpoint")).isFalse();
        }
    }
    @Test void sharedVendorUrlHasIndependentTenantApplicationApprovalsAndCannotCrossRedeem() throws Exception {
        Fixture a=fixture("mcp-a"),b=fixture("mcp-b");String id=url();
        trust(a,id,"none",List.of("http://127.0.0.1/callback"));trust(b,id,"none",List.of("http://127.0.0.1/callback"));
        serve(id,document(id,"none",List.of("http://127.0.0.1/callback")));
        JsonNode ta=tokens(code(a,id,CALLBACK,true)),tb=tokens(code(b,id,CALLBACK,true));
        assertThat(claims(ta.path("access_token").asText()).get("tenant_id")).isEqualTo(a.tenant.id);
        assertThat(claims(tb.path("access_token").asText()).get("tenant_id")).isEqualTo(b.tenant.id);
        assertThat(audiences(claims(tb.path("access_token").asText()))).containsExactly(b.audience);
        MvcResult wrongTenant=authorization(a,id,CALLBACK,"openid",b.audience,challenge(),"S256",new MockHttpSession());
        assertThat(wrongTenant.getResponse().getStatus()).isEqualTo(403);
        denied(authorization(a,id,CALLBACK,"openid",null,challenge(),"S256",new MockHttpSession()),"invalid_target");
        assertThat(com.openwolf.iam.auth.CimdClientContext.current()).isNull();
    }
    @Test void pkceIsMandatoryAndIncorrectVerifierDoesNotSpendTheCode() throws Exception {
        Fixture f=fixture("mcp-a");String id=staticClient(f,true);
        assertThat(authorization(f,id,CALLBACK,"openid",f.audience,"plain-verifier","plain",new MockHttpSession()).getResponse().getStatus()).isEqualTo(400);
        Code code=code(f,id,CALLBACK,true);
        denied(redeem(code,null,"wrong".repeat(16)),"invalid_grant");tokens(code);
    }
    @Test void removingOneApprovalRevokesItsRefreshAndDoesNotGrantOtherTenantsAccess() throws Exception {
        Fixture f=fixture("mcp-a");String id=url();JsonNode approval=trust(f,id,"none",List.of("http://127.0.0.1/callback"));
        serve(id,document(id,"none",List.of("http://127.0.0.1/callback")));
        JsonNode issued=tokens(code(f,id,CALLBACK,true));
        var removed=send(delete(base(f.tenant)+"/applications/"+f.app+"/trusted-clients/"+approval.path("id").asText())
                .param("expectedRevision",approval.path("revision").asText()),f.tenant.admin,null);
        assertThat(removed.getResponse().getStatus()).isEqualTo(204);
        denied(refresh(id,issued.path("refresh_token").asText()),"invalid_grant");
        denied(authorization(f,id,CALLBACK,"openid",f.audience,challenge(),"S256",new MockHttpSession()),"invalid_request");
    }
    @Test void tokenAndRefreshResourceCannotChangeTheGrantBinding() throws Exception {
        Fixture a=fixture("mcp-a"),b=fixture("mcp-b");String id=url();
        trust(a,id,"none",List.of("http://127.0.0.1/callback"));trust(b,id,"none",List.of("http://127.0.0.1/callback"));
        serve(id,document(id,"none",List.of("http://127.0.0.1/callback")));
        Code code=code(a,id,CALLBACK,true);
        var wrong=mvc.perform(post("/oauth/token").contentType(MediaType.APPLICATION_FORM_URLENCODED).param("client_id",id)
                .param("grant_type","authorization_code").param("code",code.code).param("redirect_uri",CALLBACK)
                .param("code_verifier",VERIFIER).param("resource",b.audience)).andReturn();
        denied(wrong,"invalid_target");JsonNode issued=tokens(code);
        denied(mvc.perform(post("/oauth/token").contentType(MediaType.APPLICATION_FORM_URLENCODED).param("client_id",id)
                .param("grant_type","refresh_token").param("refresh_token",issued.path("refresh_token").asText())
                .param("resource",b.audience)).andReturn(),"invalid_target");
        assertThat(claims(body(refresh(id,issued.path("refresh_token").asText()),200).path("access_token").asText()).get("tenant_id")).isEqualTo(a.tenant.id);
    }
    @Test void expiredPublicRefreshIsInvalidGrantAndUnexpectedCredentialsCannotDowngradeAuthentication() throws Exception {
        Fixture f=fixture("mcp-a");String id=staticClient(f,true);JsonNode issued=tokens(code(f,id,CALLBACK,true));
        String refresh=issued.path("refresh_token").asText();
        var authorization=authorizations.findByToken(refresh,org.springframework.security.oauth2.server.authorization.OAuth2TokenType.REFRESH_TOKEN);
        authorizations.save(org.springframework.security.oauth2.server.authorization.OAuth2Authorization.from(authorization)
                .refreshToken(new org.springframework.security.oauth2.core.OAuth2RefreshToken(refresh,Instant.now().minusSeconds(120),Instant.now().minusSeconds(1))).build());
        denied(refresh(id,refresh),"invalid_grant");
        var withSecret=mvc.perform(post("/oauth/token").contentType(MediaType.APPLICATION_FORM_URLENCODED).param("client_id",id)
                .param("grant_type","refresh_token").param("refresh_token",refresh).param("client_secret","unregistered")).andReturn();
        denied(withSecret,"invalid_client");
    }
    @Test void concurrentPublicRefreshCannotIssueTwoChildren() throws Exception {
        Fixture f=fixture("mcp-a");String id=staticClient(f,true);String token=tokens(code(f,id,CALLBACK,true)).path("refresh_token").asText();
        try(var pool=java.util.concurrent.Executors.newVirtualThreadPerTaskExecutor()) {
            var start=new java.util.concurrent.CountDownLatch(1);
            List<java.util.concurrent.Future<MvcResult>> results=new ArrayList<>();
            for(int i=0;i<6;i++)results.add(pool.submit(()->{start.await();return refresh(id,token);}));
            start.countDown();int successes=0;
            for(var result:results) {MvcResult value=result.get(10,java.util.concurrent.TimeUnit.SECONDS);
                if(value.getResponse().getStatus()==200)successes++;else denied(value,"invalid_grant");}
            assertThat(successes).isEqualTo(1);
        }
    }
    @Test void approvalAdministrationRejectsCrossTenantAccessAndStaleDelete() throws Exception {
        Fixture a=fixture("mcp-a"),b=fixture("mcp-b");String id=url();
        JsonNode approval=trust(a,id,"none",List.of("http://127.0.0.1/callback"));
        String endpoint=base(a.tenant)+"/applications/"+a.app+"/trusted-clients";
        assertThat(send(get(endpoint),b.tenant.admin,null).getResponse().getStatus()).isEqualTo(404);
        assertThat(send(delete(endpoint+"/"+approval.path("id").asText()).param("expectedRevision","9999"),a.tenant.admin,null)
                .getResponse().getStatus()).isEqualTo(409);
        assertThat(send(delete(endpoint+"/"+approval.path("id").asText()).param("expectedRevision",approval.path("revision").asText()),a.tenant.admin,null)
                .getResponse().getStatus()).isEqualTo(204);
        JsonNode replacement=trust(a,id,"none",List.of("http://127.0.0.1/callback"));
        assertThat(replacement.path("id").asText()).isNotEqualTo(approval.path("id").asText());
        assertThat(applications.activeAuthority(id,a.tenant.id,a.audience)).isPresent();
        verifyNoInteractions(fetcher);
    }
    @Test void metadataCannotWidenScopesOrDowngradeTheApprovedAuthenticationMethod() throws Exception {
        Fixture f=fixture("mcp-a");String id=url();trust(f,id,"none",List.of("http://127.0.0.1/callback"));
        var doc=document(id,"none",List.of("http://127.0.0.1/callback"));doc.put("scope","openid");serve(id,doc);
        var result=authorization(f,id,CALLBACK,"openid "+READ,f.audience,challenge(),"S256",new MockHttpSession());
        assertThat(result.getResponse().getHeader("Location")).contains("error=invalid_scope");
        String privateId=url();trust(f,privateId,"private_key_jwt",List.of("http://127.0.0.1/callback"));
        serve(privateId,document(privateId,"none",List.of("http://127.0.0.1/callback")));
        denied(authorization(f,privateId,CALLBACK,"openid",f.audience,challenge(),"S256",new MockHttpSession()),"invalid_request");
    }
    @Test void sameTenantApplicationsKeepSeparateApprovalsAndRevocationBoundaries() throws Exception {
        Fixture a=fixture("mcp-a");Tenant t=a.tenant;
        String audience="https://mcp.example/second/"+t.s;String second=app(t,"second",audience);
        entitle(t,second,a.person,List.of(READ));Fixture b=new Fixture(t,second,audience,a.person);
        String id="https://ai.example/clients/"+"long-path-".repeat(20)+UUID.randomUUID()+".json";
        JsonNode approval=trust(a,id,"none",List.of("http://127.0.0.1/callback"));trust(b,id,"none",List.of("http://127.0.0.1/callback"));
        serve(id,document(id,"none",List.of("http://127.0.0.1/callback")));
        JsonNode first=tokens(code(a,id,CALLBACK,true)),other=tokens(code(b,id,CALLBACK,true));
        assertThat(send(delete(base(t)+"/applications/"+a.app+"/trusted-clients/"+approval.path("id").asText())
                .param("expectedRevision",approval.path("revision").asText()),t.admin,null).getResponse().getStatus()).isEqualTo(204);
        denied(refresh(id,first.path("refresh_token").asText()),"invalid_grant");
        assertThat(audiences(claims(body(refresh(id,other.path("refresh_token").asText()),200).path("access_token").asText()))).containsExactly(b.audience);
    }
    @Test void ambiguousResourceAcrossTenantsIsRejectedWithoutAnyFetch() throws Exception {
        Fixture a=fixture("mcp-a"),b=fixture("mcp-b");
        String app=app(b.tenant,"same-resource",a.audience);
        Fixture ambiguous=new Fixture(b.tenant,app,a.audience,b.person);String id=url();
        trust(a,id,"none",List.of("http://127.0.0.1/callback"));trust(ambiguous,id,"none",List.of("http://127.0.0.1/callback"));
        denied(authorization(a,id,CALLBACK,"openid",a.audience,challenge(),"S256",new MockHttpSession()),"invalid_request");
        verifyNoInteractions(fetcher);
    }
    @Test void rememberedConsentNeverSkipsTheCimdScreenAndDenialCarriesIssuer() throws Exception {
        Fixture f=fixture("mcp-a");String id=url();trust(f,id,"none",List.of("http://127.0.0.1/callback"));
        var doc=document(id,"none",List.of("http://127.0.0.1/callback"));doc.put("client_name","Untrusted\u202e<script>Name</script>");serve(id,doc);
        Code first=code(f,id,CALLBACK,true);tokens(first);
        MvcResult second=authorization(f,id,CALLBACK,"openid "+READ+" offline_access",f.audience,challenge(),"S256",first.session);
        String location=second.getResponse().getHeader("Location");assertThat(location).contains("/oauth2/consent").doesNotContain("code=");
        String state=query(location,"state");
        var page=mvc.perform(get("/oauth2/consent").session(first.session).with(user(f.person)).param("client_id",id).param("state",state).param("scope","attacker-value")).andReturn();
        assertThat(page.getResponse().getContentAsString()).contains("127.0.0.1", "on your device", "&lt;script&gt;", READ).doesNotContain("<script>","\u202e","attacker-value");
        var denied=mvc.perform(post("/oauth/authorize").session(first.session).with(user(f.person)).param("client_id",id).param("state",state)).andReturn();
        assertThat(denied.getResponse().getHeader("Location")).startsWith(CALLBACK).contains("error=access_denied","iss=").doesNotContain("code=");
        var silent=mvc.perform(get("/oauth/authorize").session(first.session).with(user(f.person)).queryParam("client_id",id).queryParam("response_type","code")
                .queryParam("redirect_uri",CALLBACK).queryParam("scope","openid "+READ).queryParam("resource",f.audience).queryParam("code_challenge",challenge())
                .queryParam("code_challenge_method","S256").queryParam("prompt","none")).andReturn();
        assertThat(silent.getResponse().getHeader("Location")).contains("error=consent_required","iss=").doesNotContain("code=");
        var anonymous=mvc.perform(get("/oauth/authorize").queryParam("client_id",id).queryParam("response_type","code").queryParam("redirect_uri",CALLBACK)
                .queryParam("scope","openid").queryParam("resource",f.audience).queryParam("code_challenge",challenge()).queryParam("code_challenge_method","S256").queryParam("prompt","none")).andReturn();
        assertThat(anonymous.getResponse().getHeader("Location")).contains("error=login_required","iss=").doesNotContain("code=");
    }
    @Test void cimdSupportsOAuthWithoutOpenidAndStillRequiresFreshConsent() throws Exception {
        Fixture f=fixture("mcp-a");String id=url();trust(f,id,"none",List.of("http://127.0.0.1/callback"));serve(id,document(id,"none",List.of("http://127.0.0.1/callback")));
        MockHttpSession session=new MockHttpSession();var start=authorization(f,id,CALLBACK,READ+" offline_access",f.audience,challenge(),"S256",session);
        String location=start.getResponse().getHeader("Location");assertThat(location).contains("/oauth2/consent");String state=query(location,"state");
        var approved=mvc.perform(post("/oauth/authorize").session(session).with(user(f.person)).param("client_id",id).param("state",state).param("scope",READ,"offline_access")).andReturn();
        JsonNode issued=tokens(new Code(id,query(approved.getResponse().getHeader("Location"),"code"),CALLBACK,session));
        assertThat(issued.has("id_token")).isFalse();assertThat(issued.has("refresh_token")).isTrue();body(refresh(id,issued.path("refresh_token").asText()),200);
        var onlyOpenid=authorization(f,id,CALLBACK,"openid",f.audience,challenge(),"S256",session);
        assertThat(onlyOpenid.getResponse().getHeader("Location")).contains("/oauth2/consent");
        var openidApproved=mvc.perform(post("/oauth/authorize").session(session).with(user(f.person)).param("client_id",id)
                .param("state",query(onlyOpenid.getResponse().getHeader("Location"),"state")).param("scope","openid")).andReturn();
        assertThat(openidApproved.getResponse().getHeader("Location")).contains("code=","iss=");
    }
    @Test void metadataOutageCannotBreakPublicRefreshOrIntrospectionAndLookup() throws Exception {
        Fixture f=fixture("mcp-a");String id=url();trust(f,id,"none",List.of("http://127.0.0.1/callback"));serve(id,document(id,"none",List.of("http://127.0.0.1/callback")));
        JsonNode issued=tokens(code(f,id,CALLBACK,true));var record=authorizations.findByToken(issued.path("refresh_token").asText(),org.springframework.security.oauth2.server.authorization.OAuth2TokenType.REFRESH_TOKEN);
        var caller=confidential(f.tenant,f.app,f.audience,f.tenant.s+"-introspector",List.of(READ));
        documents.evict(id);when(fetcher.fetch(id)).thenThrow(new CimdHttpFetcher.FetchFailure("offline"));clearInvocations(fetcher);
        assertThat(registrations.findById(record.getRegisteredClientId()).getClientId()).isEqualTo(id);
        assertThat(introspect(caller,issued.path("access_token").asText()).path("active").asBoolean()).isTrue();
        body(refresh(id,issued.path("refresh_token").asText()),200);verifyNoInteractions(fetcher);
    }
    @Test void publishedKeyRotationIsLoadedForUnknownKidAndOldKeyCannotComeBack() throws Exception {
        Fixture f=fixture("mcp-a");String id=url(),jwks=url();var old=new RSAKeyGenerator(2048).keyID("old").generate();var next=new RSAKeyGenerator(2048).keyID("new").generate();
        trust(f,id,"private_key_jwt",List.of("http://127.0.0.1/callback"));var doc=document(id,"private_key_jwt",List.of("http://127.0.0.1/callback"));doc.put("jwks_uri",jwks);serve(id,doc);
        serve(jwks,Map.of("keys",List.of(old.toPublicJWK().toJSONObject())));String issuer=discovery().path("issuer").asText();
        body(redeem(code(f,id,CALLBACK,true),assertion(old,id,issuer,UUID.randomUUID().toString()),VERIFIER),200);
        serve(jwks,Map.of("keys",List.of(next.toPublicJWK().toJSONObject())));
        body(redeem(code(f,id,CALLBACK,true),assertion(next,id,issuer,UUID.randomUUID().toString()),VERIFIER),200);
        denied(redeem(code(f,id,CALLBACK,true),assertion(old,id,issuer,UUID.randomUUID().toString()),VERIFIER),"invalid_client");
        denied(redeem(code(f,id,CALLBACK,true),assertion(next,id,"https://wrong-issuer.example",UUID.randomUUID().toString()),VERIFIER),"invalid_client");
        var algorithmMismatch=new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.HS256).keyID("new").build(),
                new JWTClaimsSet.Builder().issuer(id).subject(id).audience(issuer).issueTime(new Date()).expirationTime(Date.from(Instant.now().plusSeconds(60))).jwtID(UUID.randomUUID().toString()).build());
        algorithmMismatch.sign(new com.nimbusds.jose.crypto.MACSigner(new byte[32]));
        denied(redeem(code(f,id,CALLBACK,true),algorithmMismatch.serialize(),VERIFIER),"invalid_client");
        verify(fetcher,times(2)).fetch(jwks);
    }
    @Test void narrowingAnApprovalWithdrawsPendingCodesAndRefreshFamilies() throws Exception {
        Fixture f=fixture("mcp-a");String id=url();JsonNode approval=trust(f,id,"none",List.of("http://127.0.0.1/callback"));serve(id,document(id,"none",List.of("http://127.0.0.1/callback")));
        Code pending=code(f,id,CALLBACK,true);JsonNode issued=tokens(code(f,id,CALLBACK,true));
        var update=Map.of("clientId",id,"redirectUris",List.of("http://127.0.0.1/callback"),"tokenEndpointAuthMethod","none","scopes",List.of("openid"),
                "refreshTokens",false,"expectedRevision",approval.path("revision").asLong(),"displayName","Approved AI","accessTokenTtlSeconds",300);
        JsonNode replacement=body(send(put(base(f.tenant)+"/applications/"+f.app+"/trusted-clients/"+approval.path("id").asText()),f.tenant.admin,update),200);
        assertThat(replacement.path("id").asText()).isNotEqualTo(approval.path("id").asText());assertThat(replacement.path("displayName").asText()).isEqualTo("Approved AI");
        assertThat(authorizations.findByToken(issued.path("refresh_token").asText(),org.springframework.security.oauth2.server.authorization.OAuth2TokenType.REFRESH_TOKEN)).isNull();
        denied(redeem(pending,null,VERIFIER),"invalid_grant");denied(refresh(id,issued.path("refresh_token").asText()),"invalid_grant");
        assertThat(authorization(f,id,CALLBACK,"openid "+READ,f.audience,challenge(),"S256",new MockHttpSession()).getResponse().getHeader("Location")).contains("error=invalid_scope");
    }
    @Test void cimdRefreshRechecksCurrentPersonMembership() throws Exception {
        Fixture f=fixture("mcp-a");String id=url();trust(f,id,"none",List.of("http://127.0.0.1/callback"));serve(id,document(id,"none",List.of("http://127.0.0.1/callback")));
        JsonNode issued=tokens(code(f,id,CALLBACK,true));jdbc.update("update tenant_application_memberships set status='DISABLED' where application_id=?::uuid and principal_id=?",f.app,f.person);
        denied(refresh(id,issued.path("refresh_token").asText()),"invalid_grant");
    }
    @Test void publicRefreshCannotAuthenticateAConfidentialClientWithoutItsCredential() throws Exception {
        Fixture f=fixture("mcp-a");String id=f.tenant.s+"-confidential-web";
        body(send(post(base(f.tenant)+"/applications/"+f.app+"/clients"),f.tenant.admin,Map.of("clientId",id,"clientType","CONFIDENTIAL_WEB",
                "redirectUris",List.of(CALLBACK),"scopes",List.of("openid",READ,"offline_access"))),201);
        denied(refresh(id,"opaque-invalid-token"),"invalid_client");
    }
    @org.springframework.boot.test.context.TestConfiguration(proxyBeanMethods=false)
    public static class OfflineMetadata {
        @org.springframework.context.annotation.Bean(name="cimdHttpFetcher")
        public CimdHttpFetcher offlineFetcher() {
            var stub=mock(CimdHttpFetcher.class);when(stub.fetch(anyString())).thenThrow(new CimdHttpFetcher.FetchFailure("simulated vendor outage"));return stub;
        }
    }
    @Test void persistedClientAndRefreshSurviveAFreshAxiomApplicationDuringVendorOutage() throws Exception {
        Fixture f=fixture("mcp-a");String id=url();trust(f,id,"none",List.of("http://127.0.0.1/callback"));serve(id,document(id,"none",List.of("http://127.0.0.1/callback")));
        JsonNode issued=tokens(code(f,id,CALLBACK,true));String token=issued.path("refresh_token").asText();
        String registered=authorizations.findByToken(token,org.springframework.security.oauth2.server.authorization.OAuth2TokenType.REFRESH_TOKEN).getRegisteredClientId();
        List<String> args=new ArrayList<>(List.of(commandLine()));args.add("--spring.main.allow-bean-definition-overriding=true");args.add("--server.address=127.0.0.1");
        try(var restarted=new org.springframework.boot.builder.SpringApplicationBuilder(IamApplication.class,OfflineMetadata.class).run(args.toArray(String[]::new))) {
            var fresh=restarted.getBean(com.openwolf.iam.auth.CimdRegisteredClientRepository.class);
            assertThat(fresh.findById(registered).getClientId()).isEqualTo(id);
            int port=((org.springframework.boot.web.servlet.context.ServletWebServerApplicationContext)restarted).getWebServer().getPort();
            var request=new org.springframework.util.LinkedMultiValueMap<String,String>();request.add("grant_type","refresh_token");request.add("client_id",id);request.add("refresh_token",token);
            var result=new org.springframework.web.client.RestTemplate().postForEntity("http://127.0.0.1:"+port+"/oauth/token",request,String.class);
            assertThat(result.getStatusCode().value()).isEqualTo(200);JsonNode renewed=json.readTree(result.getBody());
            assertThat(renewed.path("refresh_token").asText()).isNotEqualTo(token);assertThat(claims(renewed.path("access_token").asText()).get("tenant_id")).isEqualTo(f.tenant.id);
            verifyNoInteractions(restarted.getBean(CimdHttpFetcher.class));
        }
    }
    @Test void customerCimdConsentCanBeManagedWithoutGlobalUrlLookupOrNetwork() throws Exception {
        Fixture f=fixture("mcp-a");String id=url();
        body(send(post(base(f.tenant)+"/applications/"+f.app+"/trusted-clients"),f.tenant.admin,
                Map.of("clientId",id,"redirectUris",List.of("http://127.0.0.1/callback"),"tokenEndpointAuthMethod","none","scopes",List.of("openid",READ),"population","CUSTOMER")),201);
        serve(id,document(id,"none",List.of("http://127.0.0.1/callback")));
        JsonNode created=body(send(post(base(f.tenant)+"/ciam/customers"),f.tenant.admin,Map.of("email",f.tenant.s+"@customers.invalid","displayName","Customer","initialPassword",PASSWORD)),201);
        String customer=created.path("customerId").asText();jdbc.update("update customer_identities set status='ACTIVE',email_verified_at=now() where id=?::uuid",customer);
        long version=jdbc.queryForObject("select token_version from customer_identities where id=?::uuid",Long.class,customer);
        var auth=new com.openwolf.iam.auth.CustomerAuthenticationToken(customer,f.tenant.id,version,null);MockHttpSession session=new MockHttpSession();
        var first=mvc.perform(get("/oauth/authorize").session(session).with(org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.authentication(auth))
                .queryParam("client_id",id).queryParam("response_type","code").queryParam("redirect_uri",CALLBACK).queryParam("scope","openid "+READ+" offline_access")
                .queryParam("resource",f.audience).queryParam("code_challenge",challenge()).queryParam("code_challenge_method","S256")).andReturn();
        assertThat(first.getResponse().getHeader("Location")).contains("/oauth2/consent");
        var approved=mvc.perform(post("/oauth/authorize").session(session).with(org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.authentication(auth))
                .param("client_id",id).param("state",query(first.getResponse().getHeader("Location"),"state")).param("scope",READ,"offline_access")).andReturn();
        JsonNode issued=tokens(new Code(id,query(approved.getResponse().getHeader("Location"),"code"),CALLBACK,session));
        assertThat(claims(issued.path("access_token").asText()).get("identity_kind")).isEqualTo("customer");
        documents.evict(id);clearInvocations(fetcher);
        var listed=customerConsents.list(f.tenant.id,UUID.fromString(customer));assertThat(listed).hasSize(1);var consent=listed.getFirst();
        assertThat(consent.clientId()).isEqualTo(id);assertThat(consent.applicationId()).isEqualTo(f.app);
        assertThat(customerConsents.list("mcp-b",UUID.fromString(customer))).isEmpty();
        assertThatThrownBy(()->customerConsents.withdrawRegistration(f.tenant.id,UUID.randomUUID(),consent.consentId(),"test"))
                .isInstanceOf(com.openwolf.iam.exception.EntityNotFoundException.class);
        String management="/ciam/tenants/"+f.tenant.id+"/customers/"+customer+"/oauth-consents";
        var own=org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt()
                .jwt(jwt->jwt.subject(customer).claim("tenant_id",f.tenant.id).claim("identity_kind","customer"));
        assertThat(mvc.perform(get(management).with(own)).andReturn().getResponse().getStatus()).isEqualTo(200);
        assertThat(mvc.perform(get("/ciam/tenants/"+f.tenant.id+"/customers/"+UUID.randomUUID()+"/oauth-consents").with(own))
                .andReturn().getResponse().getStatus()).isEqualTo(403);
        assertThat(mvc.perform(delete(management+"/registrations/"+consent.consentId()).with(own)).andReturn().getResponse().getStatus()).isEqualTo(200);
        denied(refresh(id,issued.path("refresh_token").asText()),"invalid_grant");verifyNoInteractions(fetcher);
    }
    @Test void trustedScopeDefaultsEnableIdentityScopesWithoutInventingBusinessAuthority() throws Exception {
        Fixture f=fixture("mcp-a");String id=url();
        JsonNode approved=body(send(post(base(f.tenant)+"/applications/"+f.app+"/trusted-clients"),f.tenant.admin,
                Map.of("clientId",id,"redirectUris",List.of("http://127.0.0.1/callback"),"tokenEndpointAuthMethod","none")),201);
        assertThat(approved.path("scopes").toString()).contains("openid","profile","email","offline_access").doesNotContain(READ);
        serve(id,document(id,"none",List.of("http://127.0.0.1/callback")));
        assertThat(authorization(f,id,CALLBACK,"openid profile email",f.audience,challenge(),"S256",new MockHttpSession()).getResponse().getHeader("Location")).contains("/oauth2/consent");
    }
    @Test void genericClientDisableAlsoWithdrawsCimdAuthorizations() throws Exception {
        Fixture f=fixture("mcp-a");String id=url();JsonNode approval=trust(f,id,"none",List.of("http://127.0.0.1/callback"));serve(id,document(id,"none",List.of("http://127.0.0.1/callback")));
        JsonNode issued=tokens(code(f,id,CALLBACK,true));
        assertThat(send(delete(base(f.tenant)+"/applications/"+f.app+"/clients/"+approval.path("id").asText()),f.tenant.admin,null).getResponse().getStatus()).isEqualTo(204);
        denied(refresh(id,issued.path("refresh_token").asText()),"invalid_grant");
    }
    @Test void cimdWithoutAnExplicitCallbackIsRejectedBeforeMetadataRetrieval() throws Exception {
        Fixture f=fixture("mcp-a");String id=url();trust(f,id,"none",List.of("http://127.0.0.1/callback"));
        var result=mvc.perform(get("/oauth/authorize").with(user(f.person)).queryParam("client_id",id).queryParam("response_type","code")
                .queryParam("scope",READ+" offline_access").queryParam("resource",f.audience).queryParam("code_challenge",challenge()).queryParam("code_challenge_method","S256")).andReturn();
        denied(result,"invalid_request");assertThat(result.getResponse().getHeader("Location")).isNull();verifyNoInteractions(fetcher);
    }
    @SuppressWarnings("unchecked")
    static List<String> audiences(Map<String,Object> claims) { Object value=claims.get("aud"); return value instanceof String text?List.of(text):(List<String>) value; }
    JsonNode discovery() throws Exception { return json.readTree(mvc.perform(get("/.well-known/oauth-authorization-server")).andReturn().getResponse().getContentAsString()); }
    static String assertion(RSAKey key,String client,String audience,String jti) throws Exception {
        Instant now=Instant.now();SignedJWT jwt=new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(key.getKeyID()).build(),
                new JWTClaimsSet.Builder().issuer(client).subject(client).audience(audience).issueTime(Date.from(now))
                        .expirationTime(Date.from(now.plusSeconds(60))).jwtID(jti).build());
        jwt.sign(new RSASSASigner(key));return jwt.serialize();
    }
}
