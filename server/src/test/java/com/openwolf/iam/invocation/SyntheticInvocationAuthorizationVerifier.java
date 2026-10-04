package com.openwolf.iam.invocation;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.UUID;

/**
 * TEST-ONLY stand-in for the not-yet-agreed Phase 2.2 authorization source: an HMAC-signed statement bound to every
 * field of the establishment claim. It exists to exercise Axiom's adapter contract; it is not a proposed protocol.
 */
public final class SyntheticInvocationAuthorizationVerifier implements InvocationAuthorizationVerifier {
    static final byte[] KEY = "synthetic-invocation-authorization-test-key-0123456789".getBytes(StandardCharsets.UTF_8);
    private static final ObjectMapper JSON = new ObjectMapper();

    /** The decision the synthetic authorization source made. */
    public record Statement(String tenantId, String brokerClientId, String securityScope, String subject,
                            String rootSessionId, UUID useCaseApplicationId, UUID entryWorkloadId,
                            String destinationAudience, Set<String> scopes, Instant notAfter, String nonce) {}

    public static String issue(Statement s) {
        return issue(s, KEY);
    }

    public static String issue(Statement s, byte[] key) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("tenant", s.tenantId()); body.put("broker", s.brokerClientId()); body.put("scope_id", s.securityScope());
        body.put("sub", s.subject()); body.put("session", s.rootSessionId());
        body.put("use_case", s.useCaseApplicationId().toString()); body.put("entry", s.entryWorkloadId().toString());
        body.put("dest", s.destinationAudience()); body.put("scopes", new TreeSet<>(s.scopes()));
        body.put("not_after", s.notAfter().getEpochSecond()); body.put("nonce", s.nonce());
        try {
            String payload = Base64.getUrlEncoder().withoutPadding().encodeToString(JSON.writeValueAsBytes(body));
            return payload + "." + mac(key, payload);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    @Override
    public Verified verify(EstablishmentClaim claim, String evidence) {
        String[] parts = evidence == null ? new String[0] : evidence.split("\\.");
        if (parts.length != 2 || !MessageDigest.isEqual(mac(KEY, parts[0]).getBytes(StandardCharsets.US_ASCII),
                parts[1].getBytes(StandardCharsets.US_ASCII))) throw new Rejected("signature");
        JsonNode b;
        try {
            b = JSON.readTree(Base64.getUrlDecoder().decode(parts[0]));
        } catch (Exception e) {
            throw new Rejected("malformed");
        }
        Set<String> scopes = new TreeSet<>();
        b.path("scopes").forEach(n -> scopes.add(n.asText()));
        Instant notAfter = Instant.ofEpochSecond(b.path("not_after").asLong());
        boolean bound = claim.tenantId().equals(b.path("tenant").asText())
                && claim.brokerClientId().equals(b.path("broker").asText())
                && claim.securityScope().equals(b.path("scope_id").asText())
                && claim.subject().equals(b.path("sub").asText())
                && String.valueOf(claim.rootSessionId()).equals(b.path("session").asText())
                && claim.useCaseApplicationId().toString().equals(b.path("use_case").asText())
                && claim.entryWorkloadId().toString().equals(b.path("entry").asText())
                && claim.destinationAudience().equals(b.path("dest").asText())
                && scopes.containsAll(claim.requestedScopes());
        if (!bound) throw new Rejected("not bound to this establishment");
        if (!notAfter.isAfter(Instant.now())) throw new Rejected("expired");
        return new Verified("synthetic:" + b.path("nonce").asText(), scopes, notAfter);
    }

    private static String mac(byte[] key, String payload) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(key, "HmacSHA256"));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(mac.doFinal(payload.getBytes(StandardCharsets.US_ASCII)));
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    @TestConfiguration
    public static class Config {
        @Bean
        @Primary
        InvocationAuthorizationVerifier syntheticInvocationAuthorizationVerifier() {
            return new SyntheticInvocationAuthorizationVerifier();
        }
    }
}
