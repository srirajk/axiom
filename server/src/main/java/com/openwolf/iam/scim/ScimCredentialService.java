package com.openwolf.iam.scim;

import com.openwolf.iam.entity.ScimProvisioningSource;
import com.openwolf.iam.repository.ScimProvisioningSourceRepository;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;

@Service
public class ScimCredentialService {
    private final ScimProvisioningSourceRepository sources;
    private final SecureRandom random = new SecureRandom();

    public ScimCredentialService(ScimProvisioningSourceRepository sources) { this.sources = sources; }

    public ScimProvisioningSource authenticate(String credential) {
        if (credential == null || credential.isBlank() || credential.indexOf('.') <= 0) throw new ScimException(401, "Invalid bearer credential");
        String selector = credential.substring(0, credential.indexOf('.'));
        String secret = credential.substring(credential.indexOf('.') + 1);
        ScimProvisioningSource source = sources.findBySelector(selector).orElseThrow(() -> new ScimException(401, "Invalid bearer credential"));
        if (source.getStatus() != ScimProvisioningSource.Status.ACTIVE || !constantTime(hash(secret), source.getSecretHash())) {
            throw new ScimException(401, "Invalid bearer credential");
        }
        return source;
    }

    public Credential issue() {
        String selector = randomValue(12);
        String secret = randomValue(32);
        return new Credential(selector, secret, hash(secret), selector + "." + secret);
    }

    private String randomValue(int bytes) {
        byte[] value = new byte[bytes]; random.nextBytes(value);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(value);
    }
    static String hash(String value) {
        try { return Base64.getUrlEncoder().withoutPadding().encodeToString(MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8))); }
        catch (Exception ex) { throw new IllegalStateException("SCIM credential hashing unavailable", ex); }
    }
    private static boolean constantTime(String left, String right) { return MessageDigest.isEqual(left.getBytes(StandardCharsets.UTF_8), right.getBytes(StandardCharsets.UTF_8)); }
    public record Credential(String selector, String secret, String secretHash, String bearer) {}
}
