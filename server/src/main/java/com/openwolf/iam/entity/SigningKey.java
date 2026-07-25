package com.openwolf.iam.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import jakarta.persistence.Version;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

import java.time.Instant;
import java.util.UUID;

@Entity
@Table(name = "signing_keys")
public class SigningKey {
    public enum State { STAGED, ACTIVE, VERIFICATION_ONLY, RETIRED }

    @Id private UUID id;
    @Column(name = "deployment_id", nullable = false) private String deploymentId;
    @Column(nullable = false) private String kid;
    @Column(nullable = false) private String algorithm;
    @Enumerated(EnumType.STRING) @Column(nullable = false) private State state;
    @Column(name = "private_key_ciphertext") private String privateKeyCiphertext;
    @JdbcTypeCode(SqlTypes.JSON) @Column(name = "public_key_json", nullable = false, columnDefinition = "jsonb") private String publicKeyJson;
    @Column(name = "created_at", nullable = false) private Instant createdAt;
    @Column(name = "activated_at") private Instant activatedAt;
    @Column(name = "retired_at") private Instant retiredAt;
    @Column(name = "verification_expires_at") private Instant verificationExpiresAt;
    @Version @Column(nullable = false) private long revision;

    protected SigningKey() {}

    public SigningKey(String deploymentId, String kid, String algorithm, State state,
                      String privateKeyCiphertext, String publicKeyJson) {
        this.id = UUID.randomUUID(); this.deploymentId = deploymentId; this.kid = kid;
        this.algorithm = algorithm; this.state = state; this.privateKeyCiphertext = privateKeyCiphertext;
        this.publicKeyJson = publicKeyJson; this.createdAt = Instant.now(); this.revision = 1;
    }

    public void activate(Instant now) { state = State.ACTIVE; activatedAt = now; retiredAt = null; verificationExpiresAt = null; }
    public void moveToVerificationOnly(Instant expiresAt) { state = State.VERIFICATION_ONLY; verificationExpiresAt = expiresAt; }
    public void retire(Instant now) { state = State.RETIRED; retiredAt = now; verificationExpiresAt = null; privateKeyCiphertext = null; }
    public UUID getId() { return id; }
    public String getDeploymentId() { return deploymentId; }
    public String getKid() { return kid; }
    public String getAlgorithm() { return algorithm; }
    public State getState() { return state; }
    public String getPrivateKeyCiphertext() { return privateKeyCiphertext; }
    public String getPublicKeyJson() { return publicKeyJson; }
    public Instant getCreatedAt() { return createdAt; }
    public Instant getActivatedAt() { return activatedAt; }
    public Instant getRetiredAt() { return retiredAt; }
    public Instant getVerificationExpiresAt() { return verificationExpiresAt; }
    public long getRevision() { return revision; }
}
