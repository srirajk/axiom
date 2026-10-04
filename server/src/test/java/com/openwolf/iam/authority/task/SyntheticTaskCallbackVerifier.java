package com.openwolf.iam.authority.task;

import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;

/**
 * Test-only callback trust anchor: an HMAC over every field of the callback claim with a key known to the test
 * "provider". It demonstrates the binding contract only; it is not a production trust anchor (decision D-3).
 */
public final class SyntheticTaskCallbackVerifier implements TaskCallbackVerifier {
    static final byte[] KEY = "phase3-synthetic-callback-key-not-for-production".getBytes(StandardCharsets.UTF_8);

    public static String sign(CallbackClaim claim) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(KEY, "HmacSHA256"));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(mac.doFinal(canonical(claim)
                    .getBytes(StandardCharsets.UTF_8)));
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    static String canonical(CallbackClaim c) {
        return String.join("\n", c.tenantId(), c.provider(), c.taskId().toString(), c.audience(),
                String.valueOf(c.issuedAt().getEpochSecond()), c.nonce(), c.eventType(), c.bodyDigest());
    }

    @Override
    public void verify(CallbackClaim claim, String signature) {
        if (signature == null || !MessageDigest.isEqual(sign(claim).getBytes(StandardCharsets.US_ASCII),
                signature.getBytes(StandardCharsets.US_ASCII))) {
            throw new Rejected("signature mismatch");
        }
    }

    @TestConfiguration
    public static class Config {
        @Bean
        @Primary
        TaskCallbackVerifier syntheticTaskCallbackVerifier() {
            return new SyntheticTaskCallbackVerifier();
        }
    }
}
