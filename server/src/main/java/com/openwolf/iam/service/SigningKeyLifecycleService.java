package com.openwolf.iam.service;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.openwolf.iam.auth.ExecutionTenant;
import com.openwolf.iam.entity.SigningKey;
import com.openwolf.iam.exception.EntityNotFoundException;
import com.openwolf.iam.exception.ResourceConflictException;
import com.openwolf.iam.repository.SigningKeyRepository;
import com.openwolf.iam.security.SecretProtector;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

@Service
@Transactional
public class SigningKeyLifecycleService {
    private static final String ALGORITHM = "RS256";
    private final SigningKeyRepository keys;
    private final SecretProtector secrets;
    private final AuditService audit;
    private final ExecutionTenant executionTenant;
    private final String deploymentId;
    private final Path legacyPath;
    private final boolean allowGeneration;
    private final long maxOverlapSeconds;

    public SigningKeyLifecycleService(SigningKeyRepository keys, SecretProtector secrets, AuditService audit,
                                      ExecutionTenant executionTenant,
                                      @Value("${iam.signing-key-deployment-id:default}") String deploymentId,
                                      @Value("${iam.signing-key-path:/app/keys/signing-key.json}") String legacyPath,
                                      @Value("${iam.signing-key-allow-generation:false}") boolean allowGeneration,
                                      @Value("${iam.signing-key-max-token-session-lifetime-seconds:${iam.auth.token-ttl-seconds:3600}}") long maxOverlapSeconds) {
        this.keys = keys; this.secrets = secrets; this.audit = audit; this.executionTenant = executionTenant;
        this.deploymentId = deploymentId; this.legacyPath = Path.of(legacyPath); this.allowGeneration = allowGeneration;
        if (maxOverlapSeconds <= 0) throw new IllegalArgumentException("signing-key overlap lifetime must be positive");
        this.maxOverlapSeconds = maxOverlapSeconds;
    }

    @Transactional
    public synchronized void ensureInitialized() {
        if (!keys.findByDeploymentIdAndState(deploymentId, SigningKey.State.ACTIVE).isEmpty()) return;
        if (!keys.findByDeploymentId(deploymentId).isEmpty()) throw new IllegalStateException("signing-key records have no active key");
        RSAKey key = loadLegacyOrGenerate();
        keys.save(new SigningKey(deploymentId, key.getKeyID(), ALGORITHM, SigningKey.State.ACTIVE,
                secrets.protect(key.toJSONString()), key.toPublicJWK().toJSONString()));
    }

    public JWKSource<SecurityContext> verificationSource() {
        ensureInitialized();
        return dynamicSource(false);
    }

    public JWKSource<SecurityContext> signingSource() {
        ensureInitialized();
        return dynamicSource(true);
    }

    @Transactional(readOnly = true)
    public List<SigningKeyView> list(String tenantId) { requireTenant(tenantId); return keys.findByDeploymentId(deploymentId).stream().map(this::view).toList(); }

    public SigningKeyView createStaged(String tenantId, HttpServletRequest request) {
        requireTenant(tenantId); RSAKey key = generate();
        SigningKey staged = keys.save(new SigningKey(deploymentId, key.getKeyID(), ALGORITHM, SigningKey.State.STAGED,
                secrets.protect(key.toJSONString()), key.toPublicJWK().toJSONString()));
        SigningKeyView result = view(staged); audit.logRequired(tenantId, audit.currentActor(), "CREATE_SIGNING_KEY", "signing_key", staged.getId().toString(), null, result, correlation(request)); return result;
    }

    public SigningKeyView activate(String tenantId, UUID id, HttpServletRequest request) {
        requireTenant(tenantId); SigningKey staged = keys.findByIdForUpdate(id).orElseThrow(() -> EntityNotFoundException.forId("Signing key", id));
        if (!deploymentId.equals(staged.getDeploymentId()) || staged.getState() != SigningKey.State.STAGED) throw new ResourceConflictException("only a staged signing key can be activated");
        Instant now = Instant.now(); SigningKey previous = keys.findByDeploymentIdAndStateForUpdate(deploymentId, SigningKey.State.ACTIVE).orElse(null);
        if (previous != null) { previous.moveToVerificationOnly(now.plusSeconds(maxOverlapSeconds)); keys.saveAndFlush(previous); }
        staged.activate(now); keys.save(staged); SigningKeyView result = view(staged);
        audit.logRequired(tenantId, audit.currentActor(), "ACTIVATE_SIGNING_KEY", "signing_key", id.toString(), null, result, correlation(request)); return result;
    }

    public void retire(String tenantId, UUID id, HttpServletRequest request) { retireInternal(tenantId, id, false, request); }
    public void emergencyRetire(String tenantId, UUID id, HttpServletRequest request) { retireInternal(tenantId, id, true, request); }

    private void retireInternal(String tenantId, UUID id, boolean emergency, HttpServletRequest request) {
        requireTenant(tenantId); SigningKey key = keys.findByIdForUpdate(id).orElseThrow(() -> EntityNotFoundException.forId("Signing key", id));
        if (!deploymentId.equals(key.getDeploymentId())) throw new ResourceConflictException("signing key is not available");
        if (key.getState() == SigningKey.State.ACTIVE && !emergency) throw new ResourceConflictException("active signing key cannot be retired");
        if (key.getState() == SigningKey.State.VERIFICATION_ONLY && !emergency && key.getVerificationExpiresAt() != null && key.getVerificationExpiresAt().isAfter(Instant.now())) throw new ResourceConflictException("verification-only key remains inside the token/session overlap window");
        key.retire(Instant.now()); keys.save(key); audit.logRequired(tenantId, audit.currentActor(), emergency ? "EMERGENCY_RETIRE_SIGNING_KEY" : "RETIRE_SIGNING_KEY", "signing_key", id.toString(), null, view(key), correlation(request));
    }

    private SigningKey active() { return keys.findByDeploymentIdAndState(deploymentId, SigningKey.State.ACTIVE).orElseThrow(() -> new IllegalStateException("no active signing key")); }
    private JWKSource<SecurityContext> dynamicSource(boolean signing) {
        return (selector, context) -> selector.select(new JWKSet(currentKeys(signing)));
    }
    private List<JWK> currentKeys(boolean signing) {
        if (signing) return List.of(parsePrivate(active()));
        Instant now = Instant.now(); List<JWK> publicKeys = new ArrayList<>();
        for (SigningKey key : keys.findByDeploymentId(deploymentId)) {
            if (key.getState() == SigningKey.State.ACTIVE || (key.getState() == SigningKey.State.VERIFICATION_ONLY
                    && key.getVerificationExpiresAt() != null && key.getVerificationExpiresAt().isAfter(now))) {
                publicKeys.add(parsePublic(key));
            }
        }
        return publicKeys;
    }
    private RSAKey loadLegacyOrGenerate() { try { if (Files.exists(legacyPath)) return validate(RSAKey.parse(Files.readString(legacyPath))); } catch (Exception ex) { throw new IllegalStateException("failed to load persisted signing key", ex); } if (!allowGeneration) throw new IllegalStateException("RSA signing key is missing and generation is disabled"); RSAKey generated = generate(); try { if (legacyPath.getParent() != null) Files.createDirectories(legacyPath.getParent()); Files.writeString(legacyPath, generated.toJSONString()); } catch (Exception ex) { throw new IllegalStateException("failed to persist signing key", ex); } return generated; }
    private RSAKey validate(RSAKey key) { if (!JWSAlgorithm.RS256.equals(key.getAlgorithm()) || !KeyUse.SIGNATURE.equals(key.getKeyUse()) || key.getKeyID() == null || key.getPrivateExponent() == null) throw new IllegalStateException("persisted signing key lacks required RS256/private/kid metadata"); return key; }
    private RSAKey generate() { try { KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA"); generator.initialize(2048); KeyPair pair = generator.generateKeyPair(); return new RSAKey.Builder((RSAPublicKey) pair.getPublic()).privateKey((RSAPrivateKey) pair.getPrivate()).keyID(UUID.randomUUID().toString()).algorithm(JWSAlgorithm.RS256).keyUse(KeyUse.SIGNATURE).build(); } catch (Exception ex) { throw new IllegalStateException("failed to generate RSA signing key", ex); } }
    private RSAKey parsePrivate(SigningKey key) { try { return validate(RSAKey.parse(secrets.reveal(key.getPrivateKeyCiphertext()))); } catch (Exception ex) { throw new IllegalStateException("stored signing key cannot be loaded", ex); } }
    private RSAKey parsePublic(SigningKey key) { try { return RSAKey.parse(key.getPublicKeyJson()).toPublicJWK(); } catch (Exception ex) { throw new IllegalStateException("stored signing public key cannot be loaded", ex); } }
    private SigningKeyView view(SigningKey key) { return new SigningKeyView(key.getId(), key.getKid(), key.getAlgorithm(), key.getState().name(), key.getCreatedAt(), key.getActivatedAt(), key.getRetiredAt(), key.getVerificationExpiresAt(), key.getRevision()); }
    private void requireTenant(String tenantId) { if (!executionTenant.require().equals(tenantId)) throw EntityNotFoundException.forId("Signing key", tenantId); }
    private static String correlation(HttpServletRequest request) { return request == null ? null : request.getHeader("X-Correlation-ID"); }
    public record SigningKeyView(UUID id, String kid, String algorithm, String state, java.time.Instant createdAt, java.time.Instant activatedAt, java.time.Instant retiredAt, java.time.Instant verificationExpiresAt, long revision) {}
}
