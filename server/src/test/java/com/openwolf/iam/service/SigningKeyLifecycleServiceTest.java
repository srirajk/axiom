package com.openwolf.iam.service;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.JWKMatcher;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.openwolf.iam.auth.ExecutionTenant;
import com.openwolf.iam.entity.SigningKey;
import com.openwolf.iam.exception.ResourceConflictException;
import com.openwolf.iam.repository.SigningKeyRepository;
import com.openwolf.iam.security.SecretProtector;
import org.junit.jupiter.api.Test;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.time.Instant;
import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class SigningKeyLifecycleServiceTest {
    private static final String TENANT = "tenant-a";

    @Test
    void activationMovesPriorActiveIntoBoundedVerificationOverlap() throws Exception {
        SigningKeyRepository repository = mock(SigningKeyRepository.class);
        ExecutionTenant tenant = tenant();
        SigningKey previous = key("old", SigningKey.State.ACTIVE);
        SigningKey staged = key("new", SigningKey.State.STAGED);
        when(repository.findByIdForUpdate(staged.getId())).thenReturn(Optional.of(staged));
        when(repository.findByDeploymentIdAndStateForUpdate("default", SigningKey.State.ACTIVE)).thenReturn(Optional.of(previous));
        when(repository.save(any())).thenAnswer(invocation -> invocation.getArgument(0));
        when(repository.saveAndFlush(any())).thenAnswer(invocation -> invocation.getArgument(0));
        SigningKeyLifecycleService service = service(repository, tenant, Files.createTempDirectory("axiom-key-test"));

        service.activate(TENANT, staged.getId(), null);

        assertThat(previous.getState()).isEqualTo(SigningKey.State.VERIFICATION_ONLY);
        assertThat(previous.getVerificationExpiresAt()).isAfter(Instant.now());
        assertThat(staged.getState()).isEqualTo(SigningKey.State.ACTIVE);
        verify(repository).saveAndFlush(previous);
    }

    @Test
    void refusesNormalRetirementInsideOverlapAndNeverRetiresActiveKey() throws Exception {
        SigningKeyRepository repository = mock(SigningKeyRepository.class);
        ExecutionTenant tenant = tenant();
        SigningKey active = key("active", SigningKey.State.ACTIVE);
        when(repository.findByIdForUpdate(active.getId())).thenReturn(Optional.of(active));
        SigningKeyLifecycleService service = service(repository, tenant, Files.createTempDirectory("axiom-key-test"));

        assertThatThrownBy(() -> service.retire(TENANT, active.getId(), null)).isInstanceOf(ResourceConflictException.class);
        verify(repository, never()).save(active);
    }

    @Test
    void publishesOnlyActiveAndUnexpiredVerificationPublicKeysAndSignsWithActivePrivateKey() throws Exception {
        RSAKey material = rsa("active-kid");
        RSAKey overlapMaterial = rsa("overlap-kid");
        SigningKey active = new SigningKey("default", material.getKeyID(), "RS256", SigningKey.State.ACTIVE, "active-cipher", material.toPublicJWK().toJSONString());
        SigningKey overlap = new SigningKey("default", overlapMaterial.getKeyID(), "RS256", SigningKey.State.VERIFICATION_ONLY, "overlap-cipher", overlapMaterial.toPublicJWK().toJSONString());
        overlap.moveToVerificationOnly(Instant.now().plusSeconds(60));
        SigningKey expired = key("expired", SigningKey.State.VERIFICATION_ONLY); expired.moveToVerificationOnly(Instant.now().minusSeconds(1));
        SigningKeyRepository repository = mock(SigningKeyRepository.class);
        when(repository.findByDeploymentIdAndState("default", SigningKey.State.ACTIVE)).thenReturn(Optional.of(active));
        when(repository.findByDeploymentId("default")).thenReturn(List.of(active, overlap, expired));
        SecretProtector secrets = mock(SecretProtector.class);
        when(secrets.reveal("active-cipher")).thenReturn(material.toJSONString());
        SigningKeyLifecycleService service = service(repository, tenant(), Files.createTempDirectory("axiom-key-test"), secrets);

        JWKSet published = new JWKSet(service.verificationSource().get(new JWKSelector(new JWKMatcher.Builder().build()), null));
        JWKSet signing = new JWKSet(service.signingSource().get(new JWKSelector(new JWKMatcher.Builder().build()), null));

        assertThat(published.getKeyByKeyId("active-kid")).isNotNull();
        assertThat(published.getKeyByKeyId("overlap-kid")).isNotNull();
        assertThat(published.getKeyByKeyId("expired")).isNull();
        assertThat(published.getKeyByKeyId("active-kid").isPrivate()).isFalse();
        assertThat(signing.getKeyByKeyId("active-kid").isPrivate()).isTrue();
        assertThat(signing.getKeys()).hasSize(1);
    }

    @Test
    void restartInitializationReusesExistingActiveRecord() throws Exception {
        SigningKeyRepository repository = mock(SigningKeyRepository.class);
        SigningKey active = key("persisted", SigningKey.State.ACTIVE);
        when(repository.findByDeploymentIdAndState("default", SigningKey.State.ACTIVE)).thenReturn(Optional.of(active));
        SigningKeyLifecycleService service = service(repository, tenant(), Files.createTempDirectory("axiom-key-test"));

        service.ensureInitialized();

        verify(repository, never()).save(any());
    }

    @Test
    void sameSourceObjectsRefreshAfterCommittedActivation() throws Exception {
        SigningKeyRepository repository = mock(SigningKeyRepository.class);
        ExecutionTenant tenant = tenant();
        SigningKey previous = key("old", SigningKey.State.ACTIVE);
        RSAKey previousMaterial = rsa("old"); RSAKey stagedMaterial = rsa("new");
        SigningKey staged = new SigningKey("default", "new", "RS256", SigningKey.State.STAGED, "staged-cipher", stagedMaterial.toPublicJWK().toJSONString());
        when(repository.findByDeploymentIdAndState("default", SigningKey.State.ACTIVE)).thenReturn(Optional.of(previous));
        when(repository.findByDeploymentId("default")).thenReturn(List.of(previous));
        when(repository.findByIdForUpdate(staged.getId())).thenReturn(Optional.of(staged));
        when(repository.findByDeploymentIdAndStateForUpdate("default", SigningKey.State.ACTIVE)).thenReturn(Optional.of(previous));
        when(repository.save(any())).thenAnswer(invocation -> invocation.getArgument(0));
        when(repository.saveAndFlush(any())).thenAnswer(invocation -> invocation.getArgument(0));
        SecretProtector secrets = mock(SecretProtector.class);
        when(secrets.reveal("cipher")).thenReturn(previousMaterial.toJSONString());
        when(secrets.reveal("staged-cipher")).thenReturn(stagedMaterial.toJSONString());
        SigningKeyLifecycleService service = service(repository, tenant, Files.createTempDirectory("axiom-key-test"), secrets);
        JWKSource<com.nimbusds.jose.proc.SecurityContext> verification = service.verificationSource();
        JWKSource<com.nimbusds.jose.proc.SecurityContext> signing = service.signingSource();

        service.activate(TENANT, staged.getId(), null);
        when(repository.findByDeploymentIdAndState("default", SigningKey.State.ACTIVE)).thenReturn(Optional.of(staged));
        when(repository.findByDeploymentId("default")).thenReturn(List.of(staged, previous));

        assertThat(verification.get(new JWKSelector(new JWKMatcher.Builder().keyID("new").build()), null)).hasSize(1);
        assertThat(verification.get(new JWKSelector(new JWKMatcher.Builder().keyID("old").build()), null)).hasSize(1);
        assertThat(signing.get(new JWKSelector(new JWKMatcher.Builder().keyID("new").build()), null)).hasSize(1);
    }

    private static SigningKeyLifecycleService service(SigningKeyRepository repository, ExecutionTenant tenant, Path path) {
        return service(repository, tenant, path, mock(SecretProtector.class));
    }
    private static SigningKeyLifecycleService service(SigningKeyRepository repository, ExecutionTenant tenant, Path path, SecretProtector secrets) {
        return new SigningKeyLifecycleService(repository, secrets, mock(AuditService.class), tenant, "default", path.toString(), false, 60);
    }
    private static ExecutionTenant tenant() { ExecutionTenant tenant = mock(ExecutionTenant.class); when(tenant.require()).thenReturn(TENANT); return tenant; }
    private static SigningKey key(String kid, SigningKey.State state) { return new SigningKey("default", kid, "RS256", state, "cipher", rsaPublic(kid)); }
    private static String rsaPublic(String kid) { try { return rsa(kid).toPublicJWK().toJSONString(); } catch (Exception ex) { throw new IllegalStateException(ex); } }
    private static RSAKey rsa(String kid) throws Exception { KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA"); generator.initialize(2048); KeyPair pair = generator.generateKeyPair(); return new RSAKey.Builder((java.security.interfaces.RSAPublicKey) pair.getPublic()).privateKey((java.security.interfaces.RSAPrivateKey) pair.getPrivate()).keyID(kid).algorithm(JWSAlgorithm.RS256).keyUse(KeyUse.SIGNATURE).build(); }
}
