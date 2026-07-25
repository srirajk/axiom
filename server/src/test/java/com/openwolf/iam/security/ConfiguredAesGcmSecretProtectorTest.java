package com.openwolf.iam.security;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class ConfiguredAesGcmSecretProtectorTest {
    private static final String KEY = Base64.getEncoder().encodeToString("01234567890123456789012345678901".getBytes(StandardCharsets.UTF_8));
    @Test
    void encryptsAndRecoversWithoutPersistingPlaintext() {
        ConfiguredAesGcmSecretProtector protector = new ConfiguredAesGcmSecretProtector(KEY);
        String ciphertext = protector.protect("upstream-client-secret");
        assertThat(ciphertext).startsWith("v1:").doesNotContain("upstream-client-secret");
        assertThat(protector.reveal(ciphertext)).isEqualTo("upstream-client-secret");
    }

    @Test
    void rejectsTamperedCiphertext() {
        ConfiguredAesGcmSecretProtector protector = new ConfiguredAesGcmSecretProtector(KEY);
        String ciphertext = protector.protect("upstream-client-secret");
        String tampered = ciphertext.substring(0, ciphertext.length() - 1) + (ciphertext.endsWith("A") ? "B" : "A");
        assertThatThrownBy(() -> protector.reveal(tampered)).isInstanceOf(IllegalStateException.class);
    }

    @Test
    void rejectsWeakOrMissingKeyMaterial() {
        assertThatThrownBy(() -> new ConfiguredAesGcmSecretProtector("d2Vhaw=="))
                .isInstanceOf(IllegalStateException.class).hasMessageContaining("32 bytes");
    }
}
