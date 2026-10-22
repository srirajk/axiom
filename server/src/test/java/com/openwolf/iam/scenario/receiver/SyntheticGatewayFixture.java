package com.openwolf.iam.scenario.receiver;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.proc.DefaultJOSEObjectTypeVerifier;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;

import java.time.Clock;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.function.Function;

/**
 * A synthetic, Axiom-neutral Gateway, receivers and recording downstream for Phase 1.9/1.10 scenarios. Every part is
 * configured by issuer, JWKS, audiences, accepted (token_use, authority_profile) pairs and client ids, so it works for
 * any authorized client set; it contains no Argus code and depends on no Argus fixture. Messages are in-memory
 * requests (path plus headers), so "zero downstream calls" is an exact count.
 */
public final class SyntheticGatewayFixture {
    private SyntheticGatewayFixture() {}

    /** Only these request headers ever cross a hop; everything else (cookies, forwarded or caller-written authority
     * headers) is dropped. Authorization is always replaced, never copied. */
    static final Set<String> FORWARDED_HEADERS = Set.of("x-request-id", "content-type");

    public record Request(String path, Map<String, List<String>> headers) {
        public static Request of(String path, String... nameValuePairs) {
            Map<String, List<String>> headers = new LinkedHashMap<>();
            for (int i = 0; i < nameValuePairs.length; i += 2) {
                headers.computeIfAbsent(nameValuePairs[i].toLowerCase(Locale.ROOT), k -> new ArrayList<>())
                        .add(nameValuePairs[i + 1]);
            }
            return new Request(path, headers);
        }

        List<String> header(String name) {
            return headers.getOrDefault(name.toLowerCase(Locale.ROOT), List.of());
        }

        Request withCredential(String path, String bearer) {
            Map<String, List<String>> next = new LinkedHashMap<>();
            headers.forEach((name, values) -> {
                if (FORWARDED_HEADERS.contains(name)) next.put(name, List.copyOf(values));
            });
            next.put("authorization", List.of("Bearer " + bearer));
            return new Request(path, Collections.unmodifiableMap(next));
        }
    }

    public record Response(int status, String error, Map<String, Object> principal) {
        static Response denied(int status, String error) { return new Response(status, error, Map.of()); }
    }

    /** A token-exchange call to the identity provider, as (status, access token or error code). */
    public interface TokenExchange {
        Result exchange(String clientId, String clientSecret, String subjectToken, String audience, String scope);

        record Result(int status, String accessToken, String error) {}
    }

    public interface Handler {
        Response handle(Request request);
    }

    /** Thrown by the verifier; carries the HTTP status and error class the receiver returns. */
    static final class Denied extends RuntimeException {
        final int status;
        final String error;

        Denied(int status, String error) {
            super(error, null, false, false);
            this.status = status;
            this.error = error;
        }
    }

    /**
     * What a hop accepts. {@code redeemers} are the acceptable client_id/azp values; {@code redeemerIsActor} requires
     * act.client_id == client_id (a workload continuing for itself, as at a Gateway); otherwise act.client_id must be
     * in {@code actors} and differ from the redeemer (a broker-issued token naming the source workload).
     */
    public record Policy(String issuer, String audience, String tenant, Set<List<String>> useProfiles,
                         Set<String> redeemers, boolean redeemerIsActor, Set<String> actors, String requiredScope,
                         long maxLifetimeSeconds, long skewSeconds) {}

    /** Ordered receiver contract; every check runs before any outbound I/O. */
    public static final class AccessTokenVerifier {
        private final Policy policy;
        private final DefaultJWTProcessor<SecurityContext> processor = new DefaultJWTProcessor<>();
        private final Clock clock;

        public AccessTokenVerifier(Policy policy, JWKSet jwks, Clock clock) {
            this.policy = policy;
            this.clock = clock;
            processor.setJWSTypeVerifier(new DefaultJOSEObjectTypeVerifier<>(new JOSEObjectType("at+jwt")));
            processor.setJWSKeySelector(new JWSVerificationKeySelector<>(JWSAlgorithm.RS256, new ImmutableJWKSet<>(jwks)));
            processor.setJWTClaimsSetVerifier((claims, context) -> { });   // explicit checks below, in order
        }

        public Map<String, Object> verify(Request request) {
            List<String> authorization = request.header("authorization");
            if (authorization.size() != 1 || !authorization.getFirst().startsWith("Bearer ")) {
                throw new Denied(401, "invalid_request");
            }
            String token = authorization.getFirst().substring("Bearer ".length()).trim();
            JWTClaimsSet claims;
            try {
                SignedJWT jwt = SignedJWT.parse(token);
                if (jwt.getHeader().getJWKURL() != null || jwt.getHeader().getX509CertURL() != null
                        || jwt.getHeader().getJWK() != null) throw new Denied(401, "invalid_token");
                claims = processor.process(jwt, null);   // RS256 only, typ at+jwt, configured keys only
            } catch (Denied denied) {
                throw denied;
            } catch (Exception invalid) {
                throw new Denied(401, "invalid_token");
            }
            long now = clock.instant().getEpochSecond();
            long skew = policy.skewSeconds();
            if (!policy.issuer().equals(claims.getIssuer())) throw new Denied(401, "invalid_token");
            if (claims.getExpirationTime() == null || claims.getIssueTime() == null
                    || claims.getExpirationTime().toInstant().getEpochSecond() <= now - skew
                    || claims.getIssueTime().toInstant().getEpochSecond() > now + skew
                    || (claims.getNotBeforeTime() != null && claims.getNotBeforeTime().toInstant().getEpochSecond() > now + skew)
                    || claims.getExpirationTime().toInstant().getEpochSecond()
                       - claims.getIssueTime().toInstant().getEpochSecond() > policy.maxLifetimeSeconds() + skew) {
                throw new Denied(401, "invalid_token");
            }
            if (claims.getAudience() == null || claims.getAudience().size() != 1
                    || !policy.audience().equals(claims.getAudience().getFirst())) throw new Denied(401, "invalid_token");
            if (!policy.tenant().equals(text(claims, "tenant_id"))) throw new Denied(401, "invalid_token");
            if (!policy.useProfiles().contains(List.of(text(claims, "token_use"), text(claims, "authority_profile")))) {
                throw new Denied(403, "wrong_token_use");
            }
            String clientId = text(claims, "client_id");
            if (clientId.isEmpty() || !clientId.equals(text(claims, "azp")) || !policy.redeemers().contains(clientId)) {
                throw new Denied(403, "wrong_redeemer");
            }
            // RFC 8693 section 4.1: the outermost act is the current actor; without act the subject acts for itself.
            Object act = claims.getClaim("act");
            String actorClient;
            if (act == null) {
                actorClient = text(claims, "sub");
                if (actorClient.isEmpty()) throw new Denied(403, "missing_actor");
            } else {
                if (!(act instanceof Map<?, ?> actor) || blank(actor.get("sub")) || blank(actor.get("client_id"))
                        || blank(actor.get("workload_id"))) throw new Denied(403, "missing_actor");
                actorClient = String.valueOf(actor.get("client_id"));
            }
            boolean actorOk = policy.redeemerIsActor() ? actorClient.equals(clientId)
                    : policy.actors().contains(actorClient) && !actorClient.equals(clientId);
            if (!actorOk) throw new Denied(403, "wrong_actor");
            if (!scopes(claims).contains(policy.requiredScope())) throw new Denied(403, "insufficient_scope");
            for (String required : List.of("sub", "sid", "authority_id")) {
                if (text(claims, required).isEmpty()) throw new Denied(403, "missing_" + required);
            }
            // A human (workforce) subject must stay bound to its root session; an autonomous service subject has none.
            if ("workforce".equals(text(claims, "identity_kind")) && text(claims, "subject_sid").isEmpty()) {
                throw new Denied(403, "missing_subject_sid");
            }
            Map<String, Object> principal = new LinkedHashMap<>(claims.getClaims());
            principal.put("__token", token);
            return principal;
        }

        private static String text(JWTClaimsSet claims, String name) {
            Object value = claims.getClaim(name);
            return value == null ? "" : String.valueOf(value);
        }

        private static boolean blank(Object value) { return value == null || String.valueOf(value).isBlank(); }

        private static List<String> scopes(JWTClaimsSet claims) {
            Object scope = claims.getClaim("scope");
            if (scope instanceof List<?> list) return list.stream().map(String::valueOf).toList();
            return scope == null ? List.of() : List.of(String.valueOf(scope).split(" "));
        }
    }

    /** Counts and keeps every request it receives; always answers 200 and enforces nothing. */
    public static final class RecordingDownstream implements Handler {
        public final List<Request> received = Collections.synchronizedList(new ArrayList<>());

        @Override
        public Response handle(Request request) {
            received.add(request);
            return new Response(200, null, Map.of());
        }
    }

    /**
     * Generic Gateway: accepts only a gateway-authorization token a workload minted for itself, then asks the
     * identity provider (as the configured broker) for the destination's token and forwards only that token.
     * Destinations are fixed configuration keyed by path; nothing in the request selects an audience or authority.
     */
    public static final class SyntheticGateway implements Handler {
        private final AccessTokenVerifier verifier;
        private final TokenExchange idp;
        private final String brokerClientId;
        private final String brokerSecret;
        private final Map<String, Destination> destinations;
        public int forwarded;

        public record Destination(String audience, String scope, Handler handler) {}

        public SyntheticGateway(AccessTokenVerifier verifier, TokenExchange idp, String brokerClientId,
                                String brokerSecret, Map<String, Destination> destinations) {
            this.verifier = verifier;
            this.idp = idp;
            this.brokerClientId = brokerClientId;
            this.brokerSecret = brokerSecret;
            this.destinations = Map.copyOf(destinations);
        }

        @Override
        public Response handle(Request request) {
            Destination destination = destinations.get(request.path());
            if (destination == null) return Response.denied(404, "unknown_destination");
            Map<String, Object> principal;
            try {
                principal = verifier.verify(request);
            } catch (Denied denied) {
                return Response.denied(denied.status, denied.error);
            }
            TokenExchange.Result exchanged = idp.exchange(brokerClientId, brokerSecret, (String) principal.get("__token"),
                    destination.audience(), destination.scope());
            if (exchanged.status() != 200) return Response.denied(502, "upstream_exchange_failed:" + exchanged.error());
            forwarded++;
            return destination.handler().handle(request.withCredential(request.path(), exchanged.accessToken()));
        }
    }

    /**
     * Generic receiver: verifies the inbound token against its policy, then calls its downstream with a credential
     * obtained for the destination (never the inbound token, with no fallback when that fails).
     */
    public static final class SyntheticReceiver implements Handler {
        private final AccessTokenVerifier verifier;
        private final Function<Map<String, Object>, String> destinationCredential;
        private final String downstreamPath;
        private final Handler downstream;
        private final Function<String, Boolean> activeCheck;
        public final List<Map<String, Object>> acceptedPrincipals = Collections.synchronizedList(new ArrayList<>());

        /** Offline receiver: signature, claims and policy only; it cannot learn of revocation before expiry. */
        public SyntheticReceiver(AccessTokenVerifier verifier, Function<Map<String, Object>, String> destinationCredential,
                                 String downstreamPath, Handler downstream) {
            this(verifier, destinationCredential, downstreamPath, downstream, null);
        }

        /**
         * Revocation-aware receiver: after the offline checks, {@code activeCheck} (for example RFC 7662 introspection)
         * must report the token active. Inactive is 401; an unavailable check fails closed with 503. Neither calls
         * downstream.
         */
        public SyntheticReceiver(AccessTokenVerifier verifier, Function<Map<String, Object>, String> destinationCredential,
                                 String downstreamPath, Handler downstream, Function<String, Boolean> activeCheck) {
            this.verifier = verifier;
            this.destinationCredential = destinationCredential;
            this.downstreamPath = downstreamPath;
            this.downstream = downstream;
            this.activeCheck = activeCheck;
        }

        @Override
        public Response handle(Request request) {
            Map<String, Object> principal;
            try {
                principal = verifier.verify(request);
            } catch (Denied denied) {
                return Response.denied(denied.status, denied.error);
            }
            if (activeCheck != null) {
                Boolean active;
                try {
                    active = activeCheck.apply((String) principal.get("__token"));
                } catch (RuntimeException unavailable) {
                    return Response.denied(503, "revocation_check_unavailable");
                }
                if (!Boolean.TRUE.equals(active)) return Response.denied(401, "inactive_token");
            }
            String credential;
            try {
                credential = destinationCredential.apply(principal);
            } catch (RuntimeException failed) {
                return Response.denied(502, "destination_credential_unavailable");
            }
            if (credential == null) return Response.denied(502, "destination_credential_unavailable");
            acceptedPrincipals.add(principal);
            Response result = downstream.handle(request.withCredential(downstreamPath, credential));
            return new Response(result.status(), result.error(), principal);
        }
    }

    /**
     * Human BFF entry: holds the human's session token and continues it as the entry workload. It never uses its own
     * service identity and forwards no caller header except the allowlist.
     */
    public static final class SyntheticBff {
        private final TokenExchange idp;
        private final String entryClientId;
        private final String entrySecret;
        private final String entryAudience;
        private final String gatewayAudience;
        private final String scope;
        private final Handler gateway;

        public SyntheticBff(TokenExchange idp, String entryClientId, String entrySecret, String entryAudience,
                            String gatewayAudience, String scope, Handler gateway) {
            this.idp = idp;
            this.entryClientId = entryClientId;
            this.entrySecret = entrySecret;
            this.entryAudience = entryAudience;
            this.gatewayAudience = gatewayAudience;
            this.scope = scope;
            this.gateway = gateway;
        }

        public Response call(String humanSessionToken, Request browserRequest) {
            TokenExchange.Result delegated = idp.exchange(entryClientId, entrySecret, humanSessionToken, entryAudience, scope);
            if (delegated.status() != 200) return Response.denied(401, "human_session_rejected:" + delegated.error());
            TokenExchange.Result continued = idp.exchange(entryClientId, entrySecret, delegated.accessToken(),
                    gatewayAudience, scope);
            if (continued.status() != 200) return Response.denied(502, "continuation_failed:" + continued.error());
            return gateway.handle(browserRequest.withCredential(browserRequest.path(), continued.accessToken()));
        }
    }
}
