package com.openwolf.iam.security;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Base64;

/** AES-GCM dev/deployment adapter; the master key is configuration, never database data. */
@Component
public final class ConfiguredAesGcmSecretProtector implements SecretProtector {
    private static final String PREFIX = "v1:";
    private static final int IV_BYTES = 12;
    private static final int TAG_BITS = 128;

    private final byte[] key;
    private final SecureRandom random = new SecureRandom();

    public ConfiguredAesGcmSecretProtector(
            @Value("${iam.secrets.master-key:}") String configuredKey) {
        if (configuredKey == null || configuredKey.isBlank()) {
            throw new IllegalStateException("iam.secrets.master-key is required for secret protection");
        }
        try {
            this.key = Base64.getDecoder().decode(configuredKey);
        } catch (IllegalArgumentException ex) {
            throw new IllegalStateException("iam.secrets.master-key must be base64", ex);
        }
        if (this.key.length != 32) {
            throw new IllegalStateException("iam.secrets.master-key must decode to exactly 32 bytes");
        }
    }

    @Override
    public String protect(String plaintext) {
        if (plaintext == null || plaintext.isBlank()) throw new IllegalArgumentException("secret is required");
        try {
            byte[] iv = new byte[IV_BYTES];
            random.nextBytes(iv);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(TAG_BITS, iv));
            byte[] ciphertext = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));
            return PREFIX + Base64.getUrlEncoder().withoutPadding().encodeToString(iv)
                    + ":" + Base64.getUrlEncoder().withoutPadding().encodeToString(ciphertext);
        } catch (GeneralSecurityException ex) {
            throw new IllegalStateException("secret protection failed", ex);
        }
    }

    @Override
    public String reveal(String protectedValue) {
        if (protectedValue == null || !protectedValue.startsWith(PREFIX)) {
            throw new IllegalArgumentException("invalid protected secret");
        }
        try {
            String[] parts = protectedValue.substring(PREFIX.length()).split(":", -1);
            if (parts.length != 2) throw new IllegalArgumentException("invalid protected secret");
            byte[] iv = Base64.getUrlDecoder().decode(parts[0]);
            byte[] ciphertext = Base64.getUrlDecoder().decode(parts[1]);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(TAG_BITS, iv));
            return new String(cipher.doFinal(ciphertext), StandardCharsets.UTF_8);
        } catch (GeneralSecurityException | IllegalArgumentException ex) {
            throw new IllegalStateException("protected secret cannot be revealed", ex);
        }
    }

}
