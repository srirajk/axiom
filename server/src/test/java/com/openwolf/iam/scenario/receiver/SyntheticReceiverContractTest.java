package com.openwolf.iam.scenario.receiver;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.PlainJWT;
import com.nimbusds.jwt.SignedJWT;
import com.openwolf.iam.scenario.receiver.SyntheticGatewayFixture.AccessTokenVerifier;
import com.openwolf.iam.scenario.receiver.SyntheticGatewayFixture.Policy;
import com.openwolf.iam.scenario.receiver.SyntheticGatewayFixture.RecordingDownstream;
import com.openwolf.iam.scenario.receiver.SyntheticGatewayFixture.Request;
import com.openwolf.iam.scenario.receiver.SyntheticGatewayFixture.Response;
import com.openwolf.iam.scenario.receiver.SyntheticGatewayFixture.SyntheticGateway;
import com.openwolf.iam.scenario.receiver.SyntheticGatewayFixture.SyntheticReceiver;
import com.openwolf.iam.scenario.receiver.SyntheticGatewayFixture.TokenExchange;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.function.Consumer;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Receiver contract against token shapes an identity provider should never issue (mock issuer, local RSA key). The
 * same verifier, Gateway and receiver classes run against real Axiom tokens in SyntheticGatewayReceiverScenarioIT.
 */
class SyntheticReceiverContractTest {
    private static final Instant NOW = Instant.parse("2026-10-02T12:00:00Z");
    private static final String ISSUER = "https://issuer.test";
    private static final String TOOL = "tool:t:resource";
    private static final RSAKey KEY = generate();
    private static final RSAKey FOREIGN = generate();
    private final Clock clock = Clock.fixed(NOW, ZoneOffset.UTC);
    private final Policy toolPolicy = new Policy(ISSUER, TOOL, "t", Set.of(List.of("delegated_access", "gateway_backend")),
            Set.of("broker"), false, Set.of("agent"), "s:invoke", 300, 30);
    private final AccessTokenVerifier verifier = new AccessTokenVerifier(toolPolicy, new JWKSet(KEY.toPublicJWK()), clock);
    private final RecordingDownstream downstream = new RecordingDownstream();
    private final SyntheticReceiver tool = new SyntheticReceiver(verifier, principal -> "stub-credential", "/downstream",
            downstream);

    @Test
    void acceptsAWellFormedResourceTokenAndReplacesTheCredential() {
        String token = sign(claims(b -> { }));
        Response r = tool.handle(Request.of("/tool", "Authorization", "Bearer " + token, "X-Request-Id", "r1",
                "Cookie", "session=abc", "X-Forwarded-Authorization", "Bearer " + token, "X-Authority-Id", "forged",
                "X-Subject", "admin"));
        assertThat(r.status()).isEqualTo(200);
        assertThat(downstream.received).hasSize(1);
        Request out = downstream.received.getFirst();
        assertThat(out.headers()).containsOnlyKeys("authorization", "x-request-id");
        assertThat(out.headers().get("authorization")).containsExactly("Bearer stub-credential");
        assertThat(out.headers().toString()).doesNotContain(token).doesNotContain("forged").doesNotContain("admin");
        assertThat(r.principal()).containsEntry("sub", "human-1");
    }

    @Test
    void rejectsEveryMalformedShapeWithZeroDownstreamCalls() throws Exception {
        Map<String, String> cases = new java.util.LinkedHashMap<>();
        cases.put("multi-aud", sign(claims(b -> b.audience(List.of(TOOL, "other")))));
        cases.put("missing-aud", sign(claims(b -> b.audience(List.<String>of()))));
        cases.put("other-aud", sign(claims(b -> b.audience("agent:t:a"))));
        cases.put("wrong-iss", sign(claims(b -> b.issuer("https://evil.test"))));
        cases.put("wrong-tenant", sign(claims(b -> b.claim("tenant_id", "t2"))));
        cases.put("expired", sign(claims(b -> b.expirationTime(Date.from(NOW.minusSeconds(60))))));
        cases.put("future-iat", sign(claims(b -> b.issueTime(Date.from(NOW.plusSeconds(120)))
                .expirationTime(Date.from(NOW.plusSeconds(300))))));
        cases.put("future-nbf", sign(claims(b -> b.notBeforeTime(Date.from(NOW.plusSeconds(120))))));
        cases.put("too-long-lived", sign(claims(b -> b.issueTime(Date.from(NOW.minusSeconds(10)))
                .expirationTime(Date.from(NOW.plusSeconds(3600))))));
        cases.put("gateway-token", sign(claims(b -> b.claim("token_use", "gateway_authorization")
                .claim("authority_profile", "workload_continuation"))));
        cases.put("exchange-subject", sign(claims(b -> b.claim("token_use", "exchange_subject"))));
        cases.put("no-token-use", sign(claims(b -> b.claim("token_use", null))));
        cases.put("self-minted-by-agent", sign(claims(b -> b.claim("client_id", "agent").claim("azp", "agent"))));
        cases.put("azp-differs", sign(claims(b -> b.claim("azp", "someone"))));
        cases.put("no-act", sign(claims(b -> b.claim("act", null))));
        cases.put("broker-as-actor", sign(claims(b -> b.claim("act", Map.of("sub", "x", "client_id", "broker",
                "workload_id", UUID.randomUUID().toString())))));
        cases.put("unlisted-actor", sign(claims(b -> b.claim("act", Map.of("sub", "x", "client_id", "sibling",
                "workload_id", UUID.randomUUID().toString())))));
        cases.put("missing-scope", sign(claims(b -> b.claim("scope", List.of("s:other")))));
        cases.put("missing-sid", sign(claims(b -> b.claim("sid", null))));
        cases.put("typ-JWT", sign(claims(b -> { }), new JOSEObjectType("JWT"), KEY, null));
        cases.put("typ-missing", sign(claims(b -> { }), null, KEY, null));
        cases.put("foreign-key", sign(claims(b -> { }), new JOSEObjectType("at+jwt"), FOREIGN, null));
        cases.put("jku-header", sign(claims(b -> { }), new JOSEObjectType("at+jwt"), KEY, URI.create("https://evil.test/jwks")));
        cases.put("alg-none", new PlainJWT(claims(b -> { })).serialize());
        SignedJWT hs = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.HS256).type(new JOSEObjectType("at+jwt"))
                .keyID(KEY.getKeyID()).build(), claims(b -> { }));
        hs.sign(new MACSigner(new byte[32]));
        cases.put("alg-HS256", hs.serialize());

        cases.forEach((name, token) -> {
            Response r = tool.handle(Request.of("/tool", "Authorization", "Bearer " + token));
            assertThat(r.status()).as(name).isIn(401, 403);
        });
        assertThat(tool.handle(Request.of("/tool")).status()).as("no credential").isEqualTo(401);
        String good = sign(claims(b -> { }));
        assertThat(tool.handle(Request.of("/tool", "Authorization", "Bearer " + good, "Authorization", "Bearer " + good))
                .status()).as("two Authorization headers").isEqualTo(401);
        assertThat(tool.handle(Request.of("/tool", "X-Subject", "human-1", "X-Authority-Id", "route-1",
                "X-Token-Use", "delegated_access")).status()).as("authority from headers only").isEqualTo(401);
        assertThat(downstream.received).as("zero downstream calls on denial").isEmpty();
    }

    @Test
    void credentialFailureNeverFallsBackToTheInboundToken() {
        RecordingDownstream sink = new RecordingDownstream();
        SyntheticReceiver failing = new SyntheticReceiver(verifier, principal -> {
            throw new IllegalStateException("exchange refused");
        }, "/downstream", sink);
        Response r = failing.handle(Request.of("/tool", "Authorization", "Bearer " + sign(claims(b -> { }))));
        assertThat(r.status()).isEqualTo(502);
        assertThat(sink.received).isEmpty();
    }

    @Test
    void gatewayAcceptsOnlySelfContinuedGatewayTokensAndForwardsOnlyTheExchangedOne() {
        Policy gatewayPolicy = new Policy(ISSUER, "gw:t", "t", Set.of(List.of("gateway_authorization",
                "workload_continuation")), Set.of("entry", "agent"), true, Set.of(), "s:invoke", 300, 30);
        RecordingDownstream destination = new RecordingDownstream();
        int[] exchanges = {0};
        TokenExchange idp = (client, secret, subject, audience, scope) -> {
            exchanges[0]++;
            return audience.equals(TOOL) ? new TokenExchange.Result(200, "exchanged-for-" + audience, null)
                    : new TokenExchange.Result(400, null, "invalid_target");
        };
        SyntheticGateway gateway = new SyntheticGateway(new AccessTokenVerifier(gatewayPolicy, new JWKSet(KEY.toPublicJWK()),
                clock), idp, "broker", "secret", Map.of("/tool", new SyntheticGateway.Destination(TOOL, "s:invoke",
                destination), "/agent", new SyntheticGateway.Destination("agent:t:missing-route", "s:invoke", destination)));
        String gatewayToken = sign(claims(b -> b.audience("gw:t").claim("token_use", "gateway_authorization")
                .claim("authority_profile", "workload_continuation").claim("client_id", "agent").claim("azp", "agent")));

        assertThat(gateway.handle(Request.of("/tool", "Authorization", "Bearer " + gatewayToken)).status()).isEqualTo(200);
        assertThat(destination.received.getFirst().headers().get("authorization")).containsExactly("Bearer exchanged-for-" + TOOL);

        // Exchange refused: 502 and nothing forwarded. Unknown path: 404 before any exchange.
        assertThat(gateway.handle(Request.of("/agent", "Authorization", "Bearer " + gatewayToken)).status()).isEqualTo(502);
        assertThat(gateway.handle(Request.of("/admin", "Authorization", "Bearer " + gatewayToken)).status()).isEqualTo(404);
        // Broker-issued and resource tokens are not Gateway input; nor is a workload token naming another actor.
        String resourceToken = sign(claims(b -> { }));
        String crossActor = sign(claims(b -> b.audience("gw:t").claim("token_use", "gateway_authorization")
                .claim("authority_profile", "workload_continuation").claim("client_id", "agent").claim("azp", "agent")
                .claim("act", Map.of("sub", "e", "client_id", "entry", "workload_id", UUID.randomUUID().toString()))));
        int before = exchanges[0];
        assertThat(gateway.handle(Request.of("/tool", "Authorization", "Bearer " + resourceToken)).status()).isEqualTo(401);
        assertThat(gateway.handle(Request.of("/tool", "Authorization", "Bearer " + crossActor)).status()).isEqualTo(403);
        assertThat(exchanges[0]).as("no exchange attempted for a rejected inbound token").isEqualTo(before);
        assertThat(destination.received).hasSize(1);
    }

    @Test
    void humanSubjectsMustCarryARootSessionButServiceSubjectsNeedNot() {
        String humanWithoutRoot = sign(claims(b -> b.claim("identity_kind", "workforce").claim("subject_sid", null)));
        assertThat(tool.handle(Request.of("/tool", "Authorization", "Bearer " + humanWithoutRoot)).error())
                .isEqualTo("missing_subject_sid");
        String service = sign(claims(b -> b.subject("agent").claim("identity_kind", "workload").claim("subject_sid", null)));
        assertThat(tool.handle(Request.of("/tool", "Authorization", "Bearer " + service)).status()).isEqualTo(200);
        assertThat(downstream.received).hasSize(1);
    }

    @Test
    void revocationAwareReceiverRejectsInactiveAndFailsClosedWhenItCannotCheck() {
        String token = sign(claims(b -> { }));
        RecordingDownstream sink = new RecordingDownstream();
        SyntheticReceiver inactive = new SyntheticReceiver(verifier, p -> "cred", "/d", sink, t -> false);
        SyntheticReceiver outage = new SyntheticReceiver(verifier, p -> "cred", "/d", sink, t -> {
            throw new IllegalStateException("introspection endpoint down");
        });
        SyntheticReceiver active = new SyntheticReceiver(verifier, p -> "cred", "/d", sink, t -> t.equals(token));
        assertThat(inactive.handle(Request.of("/t", "Authorization", "Bearer " + token)).status()).isEqualTo(401);
        assertThat(outage.handle(Request.of("/t", "Authorization", "Bearer " + token)).status()).isEqualTo(503);
        assertThat(sink.received).isEmpty();
        assertThat(active.handle(Request.of("/t", "Authorization", "Bearer " + token)).status()).isEqualTo(200);
        assertThat(sink.received).hasSize(1);
    }

    // -- token construction ---------------------------------------------------------------------------------------------

    private JWTClaimsSet claims(Consumer<JWTClaimsSet.Builder> customize) {
        JWTClaimsSet.Builder b = new JWTClaimsSet.Builder().issuer(ISSUER).subject("human-1").audience(TOOL)
                .issueTime(Date.from(NOW.minusSeconds(5))).expirationTime(Date.from(NOW.plusSeconds(200)))
                .claim("tenant_id", "t").claim("token_use", "delegated_access").claim("authority_profile", "gateway_backend")
                .claim("client_id", "broker").claim("azp", "broker").claim("scope", List.of("s:invoke"))
                .claim("act", Map.of("sub", "agent:agent:test", "client_id", "agent", "workload_id", UUID.randomUUID().toString()))
                .claim("sid", "sid-1").claim("subject_sid", "root-1").claim("authority_id", "route-4")
                .claim("identity_kind", "workforce");
        customize.accept(b);
        return b.build();
    }

    private static String sign(JWTClaimsSet claims) {
        return sign(claims, new JOSEObjectType("at+jwt"), KEY, null);
    }

    private static String sign(JWTClaimsSet claims, JOSEObjectType type, RSAKey key, URI jku) {
        try {
            JWSHeader.Builder header = new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(KEY.getKeyID());
            if (type != null) header.type(type);
            if (jku != null) header.jwkURL(jku);
            SignedJWT jwt = new SignedJWT(header.build(), claims);
            jwt.sign(new RSASSASigner(key));
            return jwt.serialize();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private static RSAKey generate() {
        try {
            return new RSAKeyGenerator(2048).keyID("k1").generate();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }
}
