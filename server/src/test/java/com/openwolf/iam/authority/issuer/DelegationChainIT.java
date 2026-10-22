package com.openwolf.iam.authority.issuer;

import com.fasterxml.jackson.databind.JsonNode;
import com.openwolf.iam.IamApplication;
import com.openwolf.iam.auth.DelegationChain;
import com.openwolf.iam.authority.AuthorityITSupport;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;

import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;

/**
 * RFC 8693 section 4.1 delegation chains over Axiom's real token, exchange, broker and introspection endpoints.
 *
 * <p>The outermost {@code act} is the current actor, regenerated from server-side identity on every exchange; on an actor
 * change (a destination workload redeeming a broker-issued token) the subject's whole {@code act} object is nested
 * verbatim; a broker hop and a same-workload continuation keep the chain unchanged and the broker is identified only by
 * {@code client_id}. A malformed chain or one deeper than {@link DelegationChain#MAX_DEPTH} is refused with
 * {@code invalid_grant} and audited; it is never truncated.
 */
@SpringBootTest(classes = IamApplication.class, webEnvironment = SpringBootTest.WebEnvironment.MOCK)
@AutoConfigureMockMvc
class DelegationChainIT extends AuthorityITSupport {
    static final String CALLBACK = "http://127.0.0.1:9/callback";

    @Autowired JwtEncoder encoder;

    /** person -> portal (entry workload) -> edge (broker) -> reports (destination workload) -> edge -> tool. */
    final class Topology {
        Tenant t;
        Svc portal, reports, sibling, edge;
        String web, person, edgeAud, toolAud, portalGateway;
    }

    private Topology topology() throws Exception { return topology("dch-a"); }

    private Topology topology(String tenant) throws Exception {
        Topology x = new Topology();
        x.t = tenant(tenant);
        Tenant t = x.t;
        x.portal = workload(t, "portal", List.of(READ));
        x.reports = workload(t, "reports", List.of(READ));
        x.sibling = workload(t, "sibling", List.of(READ));
        x.web = t.s + "-web";
        body(send(post(base(t) + "/applications/" + x.portal.appId() + "/clients"), t.admin, Map.of("clientId", x.web,
                "clientType", "PUBLIC_BROWSER", "redirectUris", List.of(CALLBACK), "postLogoutRedirectUris", List.of(),
                "scopes", List.of("openid", READ))), 201);
        x.person = principal(t.id, t.s + "-person", null);
        entitle(t, x.portal.appId(), x.person, List.of(READ));
        x.edgeAud = "edge:" + t.id + ":" + t.s;
        x.edge = confidential(t, app(t, "edge", x.edgeAud), x.edgeAud, t.s + "-edge", List.of(READ));
        body(send(post(base(t) + "/agent-exchange/brokers"), t.admin, Map.of("oauthClientId", x.edge.clientId(),
                "gatewayAudience", x.edgeAud, "scopes", List.of(READ))), 201);
        x.toolAud = "tool:" + t.id + ":" + t.s;
        app(t, "tool", x.toolAud);
        x.portalGateway = route(t, x.portal.workloadId(), "GATEWAY", null, x.edgeAud, List.of(READ));
        route(t, x.portal.workloadId(), "AGENT", x.reports.workloadId(), x.reports.audience(), List.of(READ));
        route(t, x.reports.workloadId(), "GATEWAY", null, x.edgeAud, List.of(READ));
        route(t, x.reports.workloadId(), "RESOURCE", null, x.toolAud, List.of(READ));
        route(t, x.sibling.workloadId(), "GATEWAY", null, x.edgeAud, List.of(READ));
        return x;
    }

    private static Map<String, Object> actor(Svc workload) {
        Map<String, Object> act = new LinkedHashMap<>();
        act.put("sub", workload.workloadRef());
        act.put("client_id", workload.clientId());
        act.put("workload_id", workload.workloadId());
        return act;
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> act(Map<String, Object> claims) { return (Map<String, Object>) claims.get("act"); }

    private static int depth(Object act) {
        int levels = 0;
        for (Object level = act; level != null; level = ((Map<?, ?>) level).get("act")) levels++;
        return levels;
    }

    // ------------------------------------------------------------------------------------------------ actor change

    @Test
    void anActorChangeNestsThePriorActorVerbatimAndTheBrokerIsNeverAnActor() throws Exception {
        Topology x = topology();
        String p1 = pkce(x.web, CALLBACK, x.person, "openid " + READ).accessToken();
        Map<String, Object> c1 = claims(p1);
        assertThat(c1).as("a person's login has no actor").doesNotContainKey("act");

        Map<String, Object> c2 = claims(token(exchange(x.portal, p1, x.portal.audience(), READ, Map.of())));
        assertThat(act(c2)).as("first actor, no prior").isEqualTo(actor(x.portal));

        String p3 = token(exchange(x.portal, token(exchange(x.portal, p1, x.portal.audience(), READ, Map.of())),
                x.edgeAud, READ, Map.of()));
        Map<String, Object> c3 = claims(p3);
        assertThat(act(c3)).as("same-workload continuation adds no level").isEqualTo(actor(x.portal));

        // Broker hop: the broker presents (client_id) but the current actor stays the source workload.
        String r1 = token(exchange(x.edge, p3, x.reports.audience(), READ, Map.of()));
        Map<String, Object> cr1 = claims(r1);
        assertThat(cr1.get("client_id")).isEqualTo(x.edge.clientId());
        assertThat(act(cr1)).as("broker hop keeps the chain unchanged").isEqualTo(actor(x.portal));

        // Actor change: the destination workload redeems the broker-issued token.
        String r2 = token(exchange(x.reports, r1, x.edgeAud, READ, Map.of()));
        Map<String, Object> cr2 = claims(r2);
        assertThat(cr2.get("sub")).as("the person stays the subject").isEqualTo(c1.get("sub"));
        Map<String, Object> expected = actor(x.reports);
        expected.put("act", act(cr1));
        assertThat(act(cr2)).as("prior actor nested verbatim").isEqualTo(expected);
        assertThat(act(cr2).get("act")).isEqualTo(act(cr1));
        assertThat(depth(act(cr2))).isEqualTo(2);

        // Onward broker hop to a resource: chain unchanged, broker only in client_id.
        String r3 = token(exchange(x.edge, r2, x.toolAud, READ, Map.of()));
        Map<String, Object> cr3 = claims(r3);
        assertThat(cr3.get("client_id")).isEqualTo(x.edge.clientId());
        assertThat(act(cr3)).isEqualTo(act(cr2));
        for (Map<String, Object> c : List.of(c2, c3, cr1, cr2, cr3)) {
            assertThat(json.writeValueAsString(c.get("act"))).as("the broker is never an actor")
                    .doesNotContain(x.edge.clientId());
        }

        // Introspection reports the nested chain verbatim to a same-tenant resource server.
        Svc rs = confidential(x.t, app(x.t, "rs", "rs:" + x.t.id + ":" + x.t.s), "rs:" + x.t.id + ":" + x.t.s,
                x.t.s + "-rs", List.of(READ));
        JsonNode introspected = introspect(rs, r3);
        assertThat(introspected.path("active").asBoolean()).isTrue();
        assertThat(json.convertValue(introspected.path("act"), Map.class)).isEqualTo(act(cr3));
    }

    // ----------------------------------------------------------------------------------- client credentials tokens

    @Test
    void clientCredentialsTokensCarryNoActor() throws Exception {
        Topology x = topology();
        String cc = clientCredentials(x.portal, READ);
        assertThat(claims(cc)).doesNotContainKey("act");
        Svc rs = confidential(x.t, app(x.t, "rs", "rs:" + x.t.id + ":" + x.t.s), "rs:" + x.t.id + ":" + x.t.s,
                x.t.s + "-rs", List.of(READ));
        JsonNode introspected = introspect(rs, cc);
        assertThat(introspected.path("active").asBoolean()).isTrue();
        assertThat(introspected.has("act")).isFalse();
    }

    // ----------------------------------------------------------------------------------- a service acting for itself

    /**
     * Standards-first: a service acting only for itself has no {@code act}, even after exchanging its own token; its
     * source is bound by the verified token ({@code sub}) and registration/route state, never by a self-referential actor.
     */
    @Test
    void aServiceActingForItselfHasNoActorAndItsSourceIsBoundByRouteState() throws Exception {
        Topology x = topology();
        Tenant t = x.t;
        String portalTool = route(t, x.portal.workloadId(), "RESOURCE", null, x.toolAud, List.of(READ));
        Svc rs = confidential(t, app(t, "rs", "rs:" + t.id + ":" + t.s), "rs:" + t.id + ":" + t.s, t.s + "-rs",
                List.of(READ));

        String own = clientCredentials(x.portal, READ);
        String g = token(exchange(x.portal, own, x.edgeAud, READ, Map.of()));
        Map<String, Object> cg = claims(g);
        assertThat(cg).containsEntry("sub", x.portal.clientId()).containsEntry("identity_kind", "workload")
                .containsEntry("client_id", x.portal.clientId()).containsEntry("authority_id", x.portalGateway)
                .doesNotContainKey("act");

        // Broker hop to a resource: the broker presents, the service is still only the subject.
        String res = token(exchange(x.edge, g, x.toolAud, READ, Map.of()));
        Map<String, Object> cres = claims(res);
        assertThat(cres).containsEntry("sub", x.portal.clientId()).containsEntry("client_id", x.edge.clientId())
                .containsEntry("token_use", "delegated_access").doesNotContainKey("act");
        JsonNode introspected = introspect(rs, res);
        assertThat(introspected.path("active").asBoolean()).isTrue();
        assertThat(introspected.has("act")).isFalse();
        assertThat(introspect(rs, g).path("active").asBoolean()).isTrue();

        // Takeover: another workload continues the service's work; it is the only actor, the service stays sub.
        String r1 = token(exchange(x.edge, g, x.reports.audience(), READ, Map.of()));
        assertThat(claims(r1)).containsEntry("sub", x.portal.clientId()).doesNotContainKey("act");
        String r2 = token(exchange(x.reports, r1, x.edgeAud, READ, Map.of()));
        Map<String, Object> cr2 = claims(r2);
        assertThat(cr2).containsEntry("sub", x.portal.clientId());
        assertThat(act(cr2)).isEqualTo(actor(x.reports));
        String r3 = token(exchange(x.edge, r2, x.toolAud, READ, Map.of()));
        assertThat(act(claims(r3))).as("broker hop after the takeover keeps the chain").isEqualTo(actor(x.reports));

        // Actor substitution and wrong presenters.
        denied(exchange(x.sibling, r1, x.edgeAud, READ, Map.of()), "invalid_grant");
        denied(exchange(x.portal, r1, x.edgeAud, READ, Map.of()), "invalid_grant");
        denied(exchange(x.sibling, g, x.toolAud, READ, Map.of()), "invalid_grant");
        denied(exchange(x.reports, g, x.edgeAud, READ, Map.of()), "invalid_grant");
        denied(exchange(x.edge, own, x.toolAud, READ, Map.of()), "invalid_grant");
        // A sibling's self-acting authorization never reaches the portal's routes.
        String siblingG = token(exchange(x.sibling, clientCredentials(x.sibling, READ), x.edgeAud, READ, Map.of()));
        assertThat(claims(siblingG)).doesNotContainKey("act");
        assertThat(exchange(x.edge, siblingG, x.toolAud, READ, Map.of()).getResponse().getStatus()).isIn(400, 401);
        assertThat(exchange(x.edge, siblingG, x.reports.audience(), READ, Map.of()).getResponse().getStatus())
                .isIn(400, 401);
        // Source binding comes from verified state, not from the token alone: an otherwise valid self-acting
        // authorization whose sub, or whose route, names a different workload is refused (re-signed with Axiom's key).
        String siblingGatewayRoute = String.valueOf(claims(siblingG).get("authority_id"));
        denied(exchange(x.edge, resign(g, null, Map.of("sub", x.sibling.clientId())), x.toolAud, READ, Map.of()),
                "invalid_grant");
        denied(exchange(x.edge, resign(g, null, Map.of("authority_id", siblingGatewayRoute)), x.toolAud, READ, Map.of()),
                "invalid_grant");
        denied(exchange(x.reports, resign(r1, null, Map.of("sub", x.sibling.clientId())), x.edgeAud, READ, Map.of()),
                "invalid_grant");
        assertThat(act(claims(token(exchange(x.edge, resign(g, null, Map.of()), x.toolAud, READ, Map.of())))))
                .as("control: a faithful re-signing is accepted").isNull();
        // Another tenant's broker cannot redeem it.
        Topology other = topology("dch-b");
        denied(exchange(other.edge, g, other.toolAud, READ, Map.of()), "invalid_grant");

        // Route revocation withdraws the source binding at once (as for any chain, each token is bound to the route its
        // authority_id names): the gateway authorization and its next hop stop; the resource token stops with its route.
        body(send(post(base(t) + "/agent-exchange/routes/" + x.portalGateway + "/revoke"), t.admin, Map.of()), 200);
        assertThat(introspect(rs, g).path("active").asBoolean()).isFalse();
        denied(exchange(x.edge, g, x.toolAud, READ, Map.of()), "invalid_grant");
        assertThat(introspect(rs, res).path("active").asBoolean()).isTrue();
        body(send(post(base(t) + "/agent-exchange/routes/" + portalTool + "/revoke"), t.admin, Map.of()), 200);
        assertThat(introspect(rs, res).path("active").asBoolean()).isFalse();
    }

    @Test
    void suspendingTheSourceServiceWithdrawsItsSelfActingTokens() throws Exception {
        Topology x = topology();
        Tenant t = x.t;
        route(t, x.portal.workloadId(), "RESOURCE", null, x.toolAud, List.of(READ));
        Svc rs = confidential(t, app(t, "rs", "rs:" + t.id + ":" + t.s), "rs:" + t.id + ":" + t.s, t.s + "-rs",
                List.of(READ));
        String g = token(exchange(x.portal, clientCredentials(x.portal, READ), x.edgeAud, READ, Map.of()));
        String res = token(exchange(x.edge, g, x.toolAud, READ, Map.of()));
        assertThat(introspect(rs, res).path("active").asBoolean()).isTrue();
        body(send(post(base(t) + "/ciam/agent-workloads/" + x.portal.workloadId() + "/suspend"), t.admin, null), 200);
        assertThat(introspect(rs, g).path("active").asBoolean()).isFalse();
        assertThat(introspect(rs, res).path("active").asBoolean()).isFalse();
        denied(exchange(x.edge, g, x.toolAud, READ, Map.of()), "invalid_grant");
    }

    // ------------------------------------------------------------------------------------------- existing denials

    @Test
    void existingDenialsStillHold() throws Exception {
        Topology x = topology();
        String p1 = pkce(x.web, CALLBACK, x.person, "openid " + READ).accessToken();
        String p2 = token(exchange(x.portal, p1, x.portal.audience(), READ, Map.of()));
        String p3 = token(exchange(x.portal, p2, x.edgeAud, READ, Map.of()));
        String r1 = token(exchange(x.edge, p3, x.reports.audience(), READ, Map.of()));

        // A workload that is not the routed destination cannot take over the chain.
        denied(exchange(x.sibling, r1, x.edgeAud, READ, Map.of()), "invalid_grant");
        // The source cannot redeem its own broker-issued token as if it were the destination.
        denied(exchange(x.portal, r1, x.edgeAud, READ, Map.of()), "invalid_grant");
        // A non-broker cannot use the broker path; an unrouted target stays refused.
        denied(exchange(x.sibling, p3, x.reports.audience(), READ, Map.of()), "invalid_grant");
        assertThat(exchange(x.edge, p3, "unrouted:" + x.t.s, READ, Map.of()).getResponse().getStatus()).isIn(400, 401);
        // Widening stays refused.
        assertThat(exchange(x.reports, r1, x.edgeAud, READ + " " + WRITE, Map.of()).getResponse().getStatus())
                .isIn(400, 401);
        // Resource tokens are terminal.
        String r2 = token(exchange(x.reports, r1, x.edgeAud, READ, Map.of()));
        String r3 = token(exchange(x.edge, r2, x.toolAud, READ, Map.of()));
        assertThat(exchange(x.edge, r3, x.toolAud, READ, Map.of()).getResponse().getStatus()).isIn(400, 401);
        assertThat(exchange(x.reports, r3, x.edgeAud, READ, Map.of()).getResponse().getStatus()).isIn(400, 401);
    }

    // -------------------------------------------------------------------------------------- malformed and deep chains

    /** Re-signs a real issued token with Axiom's own key, replacing only its {@code act} claim. */
    private String resign(String token, Object act) throws Exception {
        return resign(token, act, Map.of());
    }

    /** As {@link #resign(String, Object)}, also replacing the given top-level claims. */
    private String resign(String token, Object act, Map<String, Object> replaced) throws Exception {
        Map<String, Object> claims = new LinkedHashMap<>(claims(token));
        if (act == null) claims.remove("act"); else claims.put("act", act);
        claims.putAll(replaced);
        JwtClaimsSet.Builder builder = JwtClaimsSet.builder();
        claims.forEach((name, value) -> {
            if (List.of("iat", "exp", "nbf").contains(name)) {
                builder.claim(name, Instant.ofEpochSecond(((Number) value).longValue()));
            } else {
                builder.claim(name, value);
            }
        });
        return encoder.encode(JwtEncoderParameters.from(
                JwsHeader.with(SignatureAlgorithm.RS256).type("at+jwt").build(), builder.build())).getTokenValue();
    }

    private static Map<String, Object> level(String sub, Object nested) {
        Map<String, Object> level = new LinkedHashMap<>();
        level.put("sub", sub);
        level.put("client_id", sub + "-client");
        if (nested != null) level.put("act", nested);
        return level;
    }

    /** {@code top} with {@code extra} synthetic prior actors nested beneath its existing chain. */
    @SuppressWarnings("unchecked")
    private static Map<String, Object> deepen(Map<String, Object> top, int extra) {
        Object deepest = null;
        for (int i = extra; i >= 1; i--) deepest = level("agent:prior-" + i, deepest);
        Map<String, Object> copy = new LinkedHashMap<>(top);
        Map<String, Object> cursor = copy;
        while (cursor.get("act") != null) {
            Map<String, Object> next = new LinkedHashMap<>((Map<String, Object>) cursor.get("act"));
            cursor.put("act", next);
            cursor = next;
        }
        if (deepest != null) cursor.put("act", deepest);
        return copy;
    }

    @Test
    void malformedAndOverDeepChainsAreRefusedNeverTruncated() throws Exception {
        Topology x = topology();
        String p1 = pkce(x.web, CALLBACK, x.person, "openid " + READ).accessToken();
        String p3 = token(exchange(x.portal, token(exchange(x.portal, p1, x.portal.audience(), READ, Map.of())),
                x.edgeAud, READ, Map.of()));
        String r1 = token(exchange(x.edge, p3, x.reports.audience(), READ, Map.of()));
        String r2 = token(exchange(x.reports, r1, x.edgeAud, READ, Map.of()));
        Map<String, Object> top = act(claims(r2));

        // Control: a faithful re-signing is accepted, so every refusal below is the chain check, not the signature.
        assertThat(act(claims(token(exchange(x.edge, resign(r2, top), x.toolAud, READ, Map.of()))))).isEqualTo(top);

        // Broker hop (same actor): a chain of exactly MAX_DEPTH levels passes unchanged; one more level is refused.
        Map<String, Object> five = deepen(top, DelegationChain.MAX_DEPTH - depth(top));
        assertThat(depth(five)).isEqualTo(DelegationChain.MAX_DEPTH);
        Map<String, Object> issued = act(claims(token(exchange(x.edge, resign(r2, five), x.toolAud, READ, Map.of()))));
        assertThat(issued).as("kept verbatim").isEqualTo(five);
        denied(exchange(x.edge, resign(r2, deepen(top, DelegationChain.MAX_DEPTH + 1 - depth(top))), x.toolAud, READ,
                Map.of()), "invalid_grant");

        // Actor change at MAX_DEPTH: nesting would make MAX_DEPTH + 1 levels, so the exchange is refused.
        Map<String, Object> r1Act = act(claims(r1));
        String r1Four = resign(r1, deepen(r1Act, DelegationChain.MAX_DEPTH - 1 - depth(r1Act)));
        assertThat(depth(act(claims(token(exchange(x.reports, r1Four, x.edgeAud, READ, Map.of()))))))
                .isEqualTo(DelegationChain.MAX_DEPTH);
        String r1Five = resign(r1, deepen(r1Act, DelegationChain.MAX_DEPTH - depth(r1Act)));
        denied(exchange(x.reports, r1Five, x.edgeAud, READ, Map.of()), "invalid_grant");

        // Malformed prior actors under an otherwise valid current actor.
        List<Object> malformed = new ArrayList<>();
        malformed.add("agent:not-an-object");
        malformed.add(List.of(level("agent:in-a-list", null)));
        malformed.add(Map.of("client_id", "no-sub"));
        malformed.add(Map.of("sub", ""));
        malformed.add(Map.of("sub", 7));
        malformed.add(Map.of("sub", "agent:numeric-client", "client_id", 7));
        malformed.add(Map.of("sub", "agent:bad-nested", "act", "agent:string"));
        for (Object prior : malformed) {
            Map<String, Object> bad = new LinkedHashMap<>(top);
            bad.put("act", prior);
            denied(exchange(x.edge, resign(r2, bad), x.toolAud, READ, Map.of()), "invalid_grant");
            denied(exchange(x.reports, resign(r1, Map.of("sub", r1Act.get("sub"), "client_id", r1Act.get("client_id"),
                    "workload_id", r1Act.get("workload_id"), "act", prior)), x.edgeAud, READ, Map.of()), "invalid_grant");
        }
        Integer denials = jdbc.queryForObject("SELECT count(*) FROM audit_log WHERE tenant_id = ? AND action = "
                + "'TOKEN_EXCHANGE_DENIED'", Integer.class, x.t.id);
        assertThat(denials).as("every refusal is audited").isGreaterThanOrEqualTo(2 + 2 * malformed.size());
    }
}
