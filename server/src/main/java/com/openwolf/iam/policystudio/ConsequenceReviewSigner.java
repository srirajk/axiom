package com.openwolf.iam.policystudio;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;

/**
 * Signs an approval over the exact {@code consequenceReviewHash} (Axiom Story C4.6). The signature is a
 * keyed HMAC-SHA256 over the approval payload (review hash + approver + decision + timestamp), so an
 * approval is tamper-evident and cryptographically bound to the precise machine consequences the human
 * saw. A stored approval whose review hash or approver was altered fails {@link #verify}.
 *
 * <p><b>No committed secret.</b> The signing key is read from env/config with NO default; if it is
 * absent the signer refuses to sign (fail-closed) rather than fall back to a known value — matching the
 * repo rule that a missing secret must fail, never silently use a committed default.
 */
@Component
public class ConsequenceReviewSigner {

    private static final String HMAC = "HmacSHA256";

    private final byte[] key;

    public ConsequenceReviewSigner(
            @Value("${iam.policy-studio.consequence-signing-key:}") String signingKey) {
        this.key = (signingKey == null || signingKey.isBlank())
                ? null : signingKey.getBytes(StandardCharsets.UTF_8);
    }

    /** Test/adhoc constructor with an explicit key. */
    public static ConsequenceReviewSigner withKey(String signingKey) {
        return new ConsequenceReviewSigner(signingKey);
    }

    public boolean isConfigured() {
        return key != null;
    }

    /** Produce the hex HMAC over the payload. Refuses (fail-closed) if no signing key is configured. */
    public String sign(String payload) {
        if (key == null) {
            throw new IllegalStateException(
                    "consequence review signing key is not configured (iam.policy-studio.consequence-signing-key); "
                            + "refusing to sign — a missing secret must fail, never fall back to a default");
        }
        try {
            Mac mac = Mac.getInstance(HMAC);
            mac.init(new SecretKeySpec(key, HMAC));
            byte[] sig = mac.doFinal(payload.getBytes(StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder(sig.length * 2);
            for (byte b : sig) {
                sb.append(Character.forDigit((b >> 4) & 0xF, 16));
                sb.append(Character.forDigit(b & 0xF, 16));
            }
            return sb.toString();
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("HMAC signing failed", e);
        }
    }

    /** Constant-time verification that {@code signature} is the HMAC of {@code payload}. */
    public boolean verify(String payload, String signature) {
        if (key == null || signature == null) {
            return false;
        }
        String expected = sign(payload);
        return MessageDigest.isEqual(
                expected.getBytes(StandardCharsets.UTF_8), signature.getBytes(StandardCharsets.UTF_8));
    }
}
