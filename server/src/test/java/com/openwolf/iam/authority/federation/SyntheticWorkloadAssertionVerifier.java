package com.openwolf.iam.authority.federation;

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
import java.util.Map;

/**
 * Test-only provider profile ("synthetic-hosted"): an HMAC-signed JSON statement standing in for a hosted platform's
 * workload credential. It illustrates the adapter contract only and is not a production trust anchor (D-4).
 */
public final class SyntheticWorkloadAssertionVerifier implements WorkloadAssertionVerifier {
    public static final String PROFILE = "synthetic-hosted";
    private static final byte[] KEY = "phase3-synthetic-workload-federation-key".getBytes(StandardCharsets.UTF_8);
    private static final ObjectMapper JSON = new ObjectMapper();

    public static String issue(Map<String, Object> claims) {
        try {
            String body = Base64.getUrlEncoder().withoutPadding().encodeToString(JSON.writeValueAsBytes(claims));
            return body + "." + mac(body);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private static String mac(String body) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(KEY, "HmacSHA256"));
        return Base64.getUrlEncoder().withoutPadding().encodeToString(mac.doFinal(body.getBytes(StandardCharsets.US_ASCII)));
    }

    @Override
    public Verified verify(String profile, String assertion) {
        try {
            if (!PROFILE.equals(profile)) throw new Rejected("unknown profile");
            int dot = assertion.lastIndexOf('.');
            String body = assertion.substring(0, dot);
            if (!MessageDigest.isEqual(mac(body).getBytes(StandardCharsets.US_ASCII),
                    assertion.substring(dot + 1).getBytes(StandardCharsets.US_ASCII))) throw new Rejected("signature");
            JsonNode c = JSON.readTree(Base64.getUrlDecoder().decode(body));
            return new Verified(c.path("iss").asText(), c.path("sub").asText(), c.path("aud").asText(),
                    Instant.ofEpochSecond(c.path("iat").asLong()), Instant.ofEpochSecond(c.path("exp").asLong()),
                    c.path("jti").asText(null));
        } catch (Rejected r) {
            throw r;
        } catch (Exception malformed) {
            throw new Rejected("malformed");
        }
    }

    @TestConfiguration
    public static class Config {
        @Bean
        @Primary
        WorkloadAssertionVerifier syntheticWorkloadAssertionVerifier() {
            return new SyntheticWorkloadAssertionVerifier();
        }
    }
}
