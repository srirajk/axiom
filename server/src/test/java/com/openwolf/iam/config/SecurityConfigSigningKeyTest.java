package com.openwolf.iam.config;

import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.test.util.ReflectionTestUtils;

import java.nio.file.Files;
import java.nio.file.Path;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;

class SecurityConfigSigningKeyTest {

    @Test
    void normalRuntimeFailsClosedWhenSigningVolumeIsEmpty(@TempDir Path directory) {
        SecurityConfig config = config(directory.resolve("signing-key.json"), false);

        assertThatThrownBy(config::jwkSource)
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("initialize it through the explicit Axiom bootstrap mode");
    }

    @Test
    void explicitBootstrapCreatesKeyAndSubsequentRuntimeKeepsKid(@TempDir Path directory) {
        Path keyPath = directory.resolve("signing-key.json");
        SecurityConfig bootstrap = config(keyPath, true);
        RSAKey created = ((com.nimbusds.jose.jwk.source.ImmutableJWKSet<?>) bootstrap.jwkSource())
                .getJWKSet().getKeys().stream().findFirst().map(key -> (RSAKey) key).orElseThrow();

        SecurityConfig runtime = config(keyPath, false);
        RSAKey loaded = ((com.nimbusds.jose.jwk.source.ImmutableJWKSet<?>) runtime.jwkSource())
                .getJWKSet().getKeys().stream().findFirst().map(key -> (RSAKey) key).orElseThrow();
        assertThat(Files.exists(keyPath)).isTrue();
        assertThat(loaded.getKeyID()).isEqualTo(created.getKeyID());
        assertThat(loaded.getAlgorithm().getName()).isEqualTo("RS256");
        assertThat(loaded.getKeyUse().identifier()).isEqualTo("sig");
    }

    @Test
    void persistedKeyWithoutRequiredMetadataFailsClosed(@TempDir Path directory) throws Exception {
        RSAKey unsuitable = new RSAKeyGenerator(2048).keyID("unsuitable").generate();
        Path keyPath = directory.resolve("signing-key.json");
        Files.writeString(keyPath, unsuitable.toJSONString());

        assertThatThrownBy(config(keyPath, false)::jwkSource)
                .isInstanceOf(IllegalStateException.class)
                .hasRootCauseMessage("persisted signing key lacks required alg=RS256/use=sig metadata; rotate the key volume deliberately");
    }

    private static SecurityConfig config(Path keyPath, boolean allowGeneration) {
        SecurityConfig config = new SecurityConfig(mock(S256PkceEnforcementFilter.class));
        ReflectionTestUtils.setField(config, "signingKeyPath", keyPath.toString());
        ReflectionTestUtils.setField(config, "signingKeyAllowGeneration", allowGeneration);
        return config;
    }
}
