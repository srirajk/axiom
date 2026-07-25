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
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

@Entity
@Table(name = "identity_sources")
public class IdentitySource {
    public enum Status { DRAFT, VALIDATED, ACTIVE, DISABLED }

    @Id private UUID id;
    @Column(name = "tenant_id", nullable = false) private String tenantId;
    @Column(name = "display_name", nullable = false) private String displayName;
    @Column(nullable = false) private String issuer;
    @Column(name = "discovery_uri", nullable = false) private String discoveryUri;
    @Column(name = "authorization_endpoint") private String authorizationEndpoint;
    @Column(name = "token_endpoint") private String tokenEndpoint;
    @Column(name = "userinfo_endpoint") private String userinfoEndpoint;
    @Column(name = "jwks_uri") private String jwksUri;
    @Column(name = "client_id", nullable = false) private String clientId;
    @Column(name = "client_secret_ciphertext", nullable = false) private String clientSecretCiphertext;
    @JdbcTypeCode(SqlTypes.JSON) @Column(name = "requested_scopes", nullable = false, columnDefinition = "jsonb")
    private List<String> requestedScopes = new ArrayList<>();
    @JdbcTypeCode(SqlTypes.JSON) @Column(name = "allowed_signing_algorithms", nullable = false, columnDefinition = "jsonb")
    private List<String> allowedSigningAlgorithms = new ArrayList<>();
    @JdbcTypeCode(SqlTypes.JSON) @Column(name = "required_claims", nullable = false, columnDefinition = "jsonb")
    private List<String> requiredClaims = new ArrayList<>();
    @JdbcTypeCode(SqlTypes.JSON) @Column(name = "required_acr_values", nullable = false, columnDefinition = "jsonb")
    private List<String> requiredAcrValues = new ArrayList<>();
    @Enumerated(EnumType.STRING) @Column(nullable = false) private Status status;
    @Version @Column(nullable = false) private long revision;
    @Column(name = "last_validated_at") private Instant lastValidatedAt;
    @Column(name = "created_at", nullable = false) private Instant createdAt;
    @Column(name = "updated_at", nullable = false) private Instant updatedAt;

    protected IdentitySource() {}

    public IdentitySource(String tenantId, String displayName, String issuer, String discoveryUri,
                          String clientId, String clientSecretCiphertext, List<String> requestedScopes,
                          List<String> allowedSigningAlgorithms, List<String> requiredClaims,
                          List<String> requiredAcrValues) {
        this.id = UUID.randomUUID(); this.tenantId = tenantId; this.displayName = displayName;
        this.issuer = issuer; this.discoveryUri = discoveryUri; this.clientId = clientId;
        this.clientSecretCiphertext = clientSecretCiphertext;
        this.requestedScopes = new ArrayList<>(requestedScopes);
        this.allowedSigningAlgorithms = new ArrayList<>(allowedSigningAlgorithms);
        this.requiredClaims = new ArrayList<>(requiredClaims);
        this.requiredAcrValues = new ArrayList<>(requiredAcrValues);
        this.status = Status.DRAFT; this.revision = 1; this.createdAt = Instant.now(); this.updatedAt = createdAt;
    }

    public void applyValidatedMetadata(String authorizationEndpoint, String tokenEndpoint,
                                       String userinfoEndpoint, String jwksUri, Instant validatedAt) {
        this.authorizationEndpoint = authorizationEndpoint; this.tokenEndpoint = tokenEndpoint;
        this.userinfoEndpoint = userinfoEndpoint; this.jwksUri = jwksUri; this.lastValidatedAt = validatedAt;
        this.status = Status.VALIDATED; this.updatedAt = validatedAt;
    }
    public void activate() { if (status != Status.VALIDATED) throw new IllegalStateException("identity source must be validated before activation"); status = Status.ACTIVE; updatedAt = Instant.now(); }
    public void disable() { status = Status.DISABLED; updatedAt = Instant.now(); }
    public void rotateSecret(String ciphertext) { clientSecretCiphertext = ciphertext; updatedAt = Instant.now(); }

    public UUID getId() { return id; } public String getTenantId() { return tenantId; }
    public String getDisplayName() { return displayName; } public String getIssuer() { return issuer; }
    public String getDiscoveryUri() { return discoveryUri; } public String getAuthorizationEndpoint() { return authorizationEndpoint; }
    public String getTokenEndpoint() { return tokenEndpoint; } public String getUserinfoEndpoint() { return userinfoEndpoint; }
    public String getJwksUri() { return jwksUri; } public String getClientId() { return clientId; }
    public String getClientSecretCiphertext() { return clientSecretCiphertext; }
    public List<String> getRequestedScopes() { return List.copyOf(requestedScopes); }
    public List<String> getAllowedSigningAlgorithms() { return List.copyOf(allowedSigningAlgorithms); }
    public List<String> getRequiredClaims() { return List.copyOf(requiredClaims); }
    public List<String> getRequiredAcrValues() { return List.copyOf(requiredAcrValues); }
    public Status getStatus() { return status; } public long getRevision() { return revision; }
    public Instant getLastValidatedAt() { return lastValidatedAt; } public Instant getCreatedAt() { return createdAt; }
    public Instant getUpdatedAt() { return updatedAt; }
}
