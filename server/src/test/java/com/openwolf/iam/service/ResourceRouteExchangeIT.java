package com.openwolf.iam.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.openwolf.iam.IamApplication;
import com.openwolf.iam.auth.CustomerAuthenticationToken;
import com.openwolf.iam.authority.AuthorityITSupport;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.web.servlet.MvcResult;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.authentication;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;

/** Real token endpoint, persisted routes, and introspection on the disposable AuthorityITSupport stores.
 * Each matrix runs for workforce/customer-session and first-hop/continuation. Customer browser authentication
 * is simulated at the session boundary; code + PKCE, issuance, exchange and all authority checks run normally.
 */
@SpringBootTest(classes = IamApplication.class, webEnvironment = SpringBootTest.WebEnvironment.MOCK)
@AutoConfigureMockMvc
class ResourceRouteExchangeIT extends AuthorityITSupport {
    private static final String CALLBACK = "http://127.0.0.1:9/callback";

    @ParameterizedTest(name = "customer={0}, continuation={1}")
    @CsvSource({"false,false", "false,true", "true,false", "true,true"})
    void activeResourceRouteIssuesOneAudienceWithPersonSubjectWorkloadActorAndBoundedExpiry(
            boolean customer, boolean continuation) throws Exception {
        Fixture f = fixture(customer, continuation, List.of(READ, WRITE), List.of(READ));
        Instant routeExpiry = Instant.now().plusSeconds(90);
        jdbc.update("UPDATE agent_exchange_routes SET expires_at = ? WHERE id = ?::uuid",
                java.sql.Timestamp.from(routeExpiry), f.routeId);
        String issued = token(redeem(f, READ));
        Map<String, Object> c = claims(issued);
        Object aud = c.get("aud");
        assertThat(aud instanceof List<?> list ? list : List.of(aud)).containsExactly(f.target.audience());
        assertThat(c).containsEntry("sub", f.person).containsEntry("tenant_id", f.tenant.id)
                .containsEntry("client_id", f.actor.clientId()).containsEntry("token_use", "delegated_access")
                .containsEntry("authority_profile", customer ? "customer_session" : "workforce")
                .containsEntry("authority_id", f.routeId);
        Object scope = c.get("scope");
        assertThat(scope instanceof List<?> list ? list : List.of(scope)).containsExactly(READ);
        assertThat(((Map<?, ?>) c.get("act")).get("sub")).isEqualTo(f.actor.workloadRef());
        assertThat(((Map<?, ?>) c.get("act")).get("client_id")).isEqualTo(f.actor.clientId());
        assertThat(((Number) c.get("exp")).longValue()).isLessThanOrEqualTo(routeExpiry.getEpochSecond())
                .isLessThanOrEqualTo(((Number) claims(f.subject).get("exp")).longValue());
        assertThat(introspect(f.target, issued).path("active").asBoolean()).isTrue();
        JsonNode audit = lastAudit(f, "TOKEN_EXCHANGE_SUCCEEDED");
        assertThat(audit.path("routeId").asText()).isEqualTo(f.routeId);
        assertThat(audit.path("destinationType").asText()).isEqualTo("RESOURCE");
    }

    @ParameterizedTest
    @CsvSource({"false,false", "false,true", "true,false", "true,true"})
    void noExplicitRouteDeniesAnOtherwiseActiveTarget(boolean customer, boolean continuation) throws Exception {
        Fixture f = fixture(customer, continuation, List.of(READ), null);
        denied(redeem(f, READ), "invalid_target");
        JsonNode audit = lastAudit(f, "TOKEN_EXCHANGE_DENIED");
        assertThat(audit.has("routeId")).isTrue();
        assertThat(audit.get("routeId").isNull()).isTrue();
        assertThat(audit.has("destinationType")).isTrue();
    }

    @ParameterizedTest
    @CsvSource({"false,false", "false,true", "true,false", "true,true"})
    void expiredRouteDeniesExchange(boolean customer, boolean continuation) throws Exception {
        Fixture f = fixture(customer, continuation, List.of(READ), List.of(READ));
        jdbc.update("UPDATE agent_exchange_routes SET created_at = now() - interval '2 minutes', expires_at = now() - interval '1 second' WHERE id = ?::uuid", f.routeId);
        denied(redeem(f, READ), "invalid_target");
    }

    @ParameterizedTest
    @CsvSource({"false,false", "false,true", "true,false", "true,true"})
    void revokedRouteDeniesAndReplacementRouteRecoversWithoutRevivingOldTokens(
            boolean customer, boolean continuation) throws Exception {
        Fixture f = fixture(customer, continuation, List.of(READ), List.of(READ));
        String old = token(redeem(f, READ));
        body(send(post(base(f.tenant) + "/agent-exchange/routes/" + f.routeId + "/revoke"), f.tenant.admin, null), 200);
        denied(redeem(f, READ), "invalid_target");
        assertThat(introspect(f.target, old).path("active").asBoolean()).isFalse();
        String replacement = route(f.tenant, f.actor.workloadId(), "RESOURCE", null, f.target.audience(), List.of(READ));
        assertThat(replacement).isNotEqualTo(f.routeId);
        assertThat(claims(token(redeem(f, READ))).get("authority_id")).isEqualTo(replacement);
        assertThat(introspect(f.target, old).path("active").asBoolean()).isFalse();
    }

    @ParameterizedTest
    @CsvSource({"false,false", "false,true", "true,false", "true,true"})
    void anotherTenantsApplicationIsRefusedAtRouteCreationAndExchange(boolean customer, boolean continuation)
            throws Exception {
        Fixture f = fixture(customer, continuation, List.of(READ), null);
        Tenant other = tenant("resource-b");
        String foreignAudience = "resource:" + other.s;
        app(other, "foreign", foreignAudience);
        body(send(post(base(f.tenant) + "/agent-exchange/routes"), f.tenant.admin, Map.of(
                "sourceWorkloadId", f.actor.workloadId(), "destinationType", "RESOURCE", "audience", foreignAudience,
                "scopes", List.of(READ), "purpose", "tenant isolation", "expiresAt", Instant.now().plusSeconds(600).toString())), 400);
        // Even a stale/corrupt route row cannot authorize a foreign tenant's audience.
        jdbc.update("INSERT INTO agent_exchange_routes (id, tenant_id, source_workload_id, destination_type, audience, "
                        + "allowed_scopes, purpose, status, created_at, expires_at, revision) "
                        + "VALUES (?, ?, ?::uuid, 'RESOURCE', ?, '[\"p3:read\"]'::jsonb, 'isolated fixture', 'ACTIVE', now(), "
                        + "now() + interval '10 minutes', 0)", UUID.randomUUID(), f.tenant.id, f.actor.workloadId(), foreignAudience);
        denied(exchange(f.actor, f.subject, foreignAudience, READ, Map.of()), "invalid_target");
    }

    @ParameterizedTest
    @CsvSource({"false,false", "false,true", "true,false", "true,true"})
    void deactivatedTargetIsRefusedAndAuditNamesTheSelectedRoute(boolean customer, boolean continuation) throws Exception {
        Fixture f = fixture(customer, continuation, List.of(READ), List.of(READ));
        String issued = token(redeem(f, READ));
        body(send(delete(base(f.tenant) + "/applications/" + f.target.appId()), f.tenant.admin, null), 204);
        denied(redeem(f, READ), "invalid_target");
        assertThat(introspect(f.actor, issued).path("active").asBoolean()).isFalse();
        JsonNode audit = lastAudit(f, "TOKEN_EXCHANGE_DENIED");
        assertThat(audit.path("routeId").asText()).isEqualTo(f.routeId);
        assertThat(audit.path("destinationType").asText()).isEqualTo("RESOURCE");
    }

    @ParameterizedTest
    @CsvSource({"false,false", "false,true", "true,false", "true,true"})
    void scopesOutsideRouteAreRefused(boolean customer, boolean continuation) throws Exception {
        Fixture f = fixture(customer, continuation, List.of(READ, WRITE), List.of(READ));
        denied(redeem(f, WRITE), "invalid_scope");
        assertThat(lastAudit(f, "TOKEN_EXCHANGE_DENIED").path("routeId").asText()).isEqualTo(f.routeId);
    }

    @ParameterizedTest
    @CsvSource({"false,false", "false,true", "true,false", "true,true"})
    void scopesOutsideThePersonsTokenAreRefused(boolean customer, boolean continuation) throws Exception {
        Fixture f = fixture(customer, continuation, List.of(READ), List.of(READ, WRITE));
        denied(redeem(f, WRITE), "invalid_scope");
    }

    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    void workforceEntitlementsAreRecheckedAfterLogin(boolean continuation) throws Exception {
        Fixture f = fixture(false, continuation, List.of(READ, WRITE), List.of(READ, WRITE));
        jdbc.update("UPDATE tenant_application_roles SET permissions = '[\"p3:read\"]'::jsonb, "
                + "permission_effects = '{\"p3:read\":\"allow\"}'::jsonb WHERE application_id = ?::uuid", f.actor.appId());
        denied(redeem(f, WRITE), continuation ? "invalid_grant" : "invalid_scope");
    }

    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    void twoMatchingRouteTypesDenyContinuation(boolean customer) throws Exception {
        Fixture f = fixture(customer, true, List.of(READ), List.of(READ));
        Svc destination = workload(f.tenant, "destination", List.of(READ));
        // One active RESOURCE and one active AGENT route may share an audience; the DB forbids duplicate same-type routes.
        route(f.tenant, f.actor.workloadId(), "RESOURCE", null, destination.audience(), List.of(READ));
        route(f.tenant, f.actor.workloadId(), "AGENT", destination.workloadId(), destination.audience(), List.of(READ));
        denied(exchange(f.actor, f.subject, destination.audience(), READ, Map.of()), "invalid_grant");
        assertThat(lastAudit(f, "TOKEN_EXCHANGE_DENIED").get("routeId").isNull()).isTrue();
    }

    @ParameterizedTest
    @CsvSource({"false,false", "false,true", "true,false", "true,true"})
    void delegatedAccessIsTerminalEvenWithAnotherActiveResourceRoute(boolean customer, boolean continuation) throws Exception {
        Fixture f = fixture(customer, continuation, List.of(READ), List.of(READ));
        String delegated = token(redeem(f, READ));
        route(f.tenant, f.actor.workloadId(), "RESOURCE", null, f.actor.audience(), List.of(READ));
        denied(exchange(f.actor, delegated, f.actor.audience(), READ, Map.of()), "invalid_grant");
        assertThat(introspect(f.target, delegated).path("active").asBoolean()).isTrue();
    }

    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    void sameApplicationAndGatewayContinuationKeepTheirExistingProfiles(boolean customer) throws Exception {
        Fixture f = fixture(customer, false, List.of(READ), List.of(READ));
        String own = token(exchange(f.actor, f.subject, f.actor.audience(), READ, Map.of()));
        assertThat(claims(own)).containsEntry("token_use", "exchange_subject")
                .containsEntry("authority_profile", customer ? "customer_session" : "workforce");
        body(send(post(base(f.tenant) + "/agent-exchange/brokers"), f.tenant.admin, Map.of(
                "oauthClientId", f.target.clientId(), "gatewayAudience", f.target.audience(), "scopes", List.of(READ))), 201);
        route(f.tenant, f.actor.workloadId(), "GATEWAY", null, f.target.audience(), List.of(READ));
        // Retire the resource edge so the continuation has a unique Gateway edge.
        body(send(post(base(f.tenant) + "/agent-exchange/routes/" + f.routeId + "/revoke"), f.tenant.admin, null), 200);
        String gateway = token(exchange(f.actor, own, f.target.audience(), READ, Map.of()));
        assertThat(claims(gateway)).containsEntry("token_use", "gateway_authorization")
                .containsEntry("authority_profile", "workload_continuation");
        String resourceAudience = "tool:" + f.tenant.s;
        app(f.tenant, "tool", resourceAudience);
        route(f.tenant, f.actor.workloadId(), "RESOURCE", null, resourceAudience, List.of(READ));
        String resource = token(exchange(f.target, gateway, resourceAudience, READ, Map.of()));
        assertThat(claims(resource)).containsEntry("token_use", "delegated_access")
                .containsEntry("authority_profile", "gateway_backend");
        assertThat(introspect(f.target, resource).path("active").asBoolean()).isTrue();
    }

    private record Fixture(Tenant tenant, Svc actor, Svc target, String person, String subject, String routeId) {}

    private Fixture fixture(boolean customer, boolean continuation, List<String> granted, List<String> routeScopes)
            throws Exception {
        Tenant t = tenant("resource-a");
        Svc actor = workload(t, "backend", List.of(READ, WRITE));
        String targetAud = "resource:" + t.s;
        Svc target = confidential(t, app(t, "resource", targetAud), targetAud, t.s + "-resource", List.of(READ, WRITE));
        String web = t.s + "-web";
        body(send(post(base(t) + "/applications/" + actor.appId() + "/clients"), t.admin, Map.of(
                "clientId", web, "clientType", "PUBLIC_BROWSER", "population", customer ? "CUSTOMER" : "WORKFORCE",
                "redirectUris", List.of(CALLBACK), "postLogoutRedirectUris", List.of(),
                "scopes", List.of("openid", READ, WRITE))), 201);
        String person;
        String subject;
        String scope = "openid " + String.join(" ", granted);
        if (customer) {
            person = body(send(post(base(t) + "/ciam/customers"), t.admin, Map.of("email", t.s + "@customers.invalid",
                    "displayName", "Customer", "initialPassword", PASSWORD)), 201).path("customerId").asText();
            jdbc.update("UPDATE customer_identities SET status = 'ACTIVE', email_verified_at = now() WHERE id = ?::uuid", person);
            long version = jdbc.queryForObject("SELECT token_version FROM customer_identities WHERE id = ?::uuid", Long.class, person);
            subject = pkce(web, CALLBACK, authentication(new CustomerAuthenticationToken(person, t.id, version, null)), scope).accessToken();
        } else {
            person = principal(t.id, t.s + "-person", null);
            entitle(t, actor.appId(), person, granted);
            subject = pkce(web, CALLBACK, person, scope).accessToken();
        }
        if (continuation) subject = token(exchange(actor, subject, actor.audience(), String.join(" ", granted), Map.of()));
        String routeId = routeScopes == null ? null : route(t, actor.workloadId(), "RESOURCE", null, targetAud, routeScopes);
        return new Fixture(t, actor, target, person, subject, routeId);
    }

    private MvcResult redeem(Fixture f, String scope) throws Exception {
        return exchange(f.actor, f.subject, f.target.audience(), scope, Map.of());
    }

    private JsonNode lastAudit(Fixture f, String action) throws Exception {
        return json.readTree(jdbc.queryForObject("SELECT after_state::text FROM audit_log WHERE tenant_id = ? "
                + "AND actor_id = ? AND action = ? ORDER BY occurred_at DESC LIMIT 1", String.class,
                f.tenant.id, f.actor.clientId(), action));
    }
}
