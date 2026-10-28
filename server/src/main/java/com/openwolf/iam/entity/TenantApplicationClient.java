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
@Table(name = "tenant_application_clients")
public class TenantApplicationClient {
    /**
     * {@code PUBLIC_BROWSER}: a browser (SPA/native) client without a secret, authorization code + S256 PKCE, optionally rotating refresh tokens after explicit opt-in.
     * {@code CONFIDENTIAL_WEB}: a server-side web client (BFF) with its own credential, authorization code + S256 PKCE
     * and, when it is granted {@code offline_access}, rotating refresh tokens. {@code CONFIDENTIAL_SERVICE}: software
     * acting as itself (client credentials, token exchange); never a person's sign-in client.
     */
    public enum Type {
        PUBLIC_BROWSER, CONFIDENTIAL_SERVICE, CONFIDENTIAL_WEB;

        /** Clients through which a person (workforce) or a customer (CIAM) signs in. */
        public boolean interactive() { return this == PUBLIC_BROWSER || this == CONFIDENTIAL_WEB; }
    }
    public enum Status { ACTIVE, DISABLED }
    /** Which population signs in through an interactive client. Service clients are always WORKFORCE (unused). */
    public enum Population { WORKFORCE, CUSTOMER }

    @Id private UUID id;
    @Column(name = "application_id", nullable = false) private UUID applicationId;
    @Column(name = "client_id", nullable = false) private String clientId;
    @Column(name = "external_client_id") private String externalClientId;
    public String getExternalClientId() { return externalClientId; }
    public void trustExternalClient(String clientId) { this.externalClientId = clientId; }
    @Enumerated(EnumType.STRING) @Column(name = "client_type", nullable = false) private Type clientType;
    @Enumerated(EnumType.STRING) @Column(nullable = false) private Status status;
    @JdbcTypeCode(SqlTypes.JSON)
    @Column(name = "allowed_scopes", nullable = false, columnDefinition = "jsonb") private List<String> allowedScopes = new ArrayList<>();
    @Enumerated(EnumType.STRING) @Column(nullable = false) private Population population = Population.WORKFORCE;
    @Version @Column(nullable = false) private long revision;
    @Column(name = "created_at", nullable = false) private Instant createdAt;
    @Column(name = "updated_at", nullable = false) private Instant updatedAt;

    protected TenantApplicationClient() {}
    public TenantApplicationClient(UUID applicationId, String clientId, Type clientType, List<String> allowedScopes) {
        this.id = UUID.randomUUID(); this.applicationId = applicationId; this.clientId = clientId;
        this.clientType = clientType; this.allowedScopes = new ArrayList<>(allowedScopes); this.status = Status.ACTIVE;
        this.revision = 1; this.createdAt = Instant.now(); this.updatedAt = this.createdAt;
    }
    public TenantApplicationClient(UUID applicationId, String clientId, Type clientType, List<String> allowedScopes,
                                   Population population) {
        this(applicationId, clientId, clientType, allowedScopes);
        this.population = population == null ? Population.WORKFORCE : population;
    }
    public void disable() { status = Status.DISABLED; updatedAt = Instant.now(); }
    public void rotateSecret() { updatedAt = Instant.now(); }
    public UUID getId() { return id; } public UUID getApplicationId() { return applicationId; }
    public String getClientId() { return clientId; } public Type getClientType() { return clientType; }
    public Status getStatus() { return status; } public Population getPopulation() { return population; } public List<String> getAllowedScopes() { return List.copyOf(allowedScopes); }
    public long getRevision() { return revision; }
    public Instant getCreatedAt() { return createdAt; } public Instant getUpdatedAt() { return updatedAt; }
}
