package com.openwolf.iam.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import jakarta.persistence.Version;

import java.time.Instant;
import java.util.UUID;

@Entity
@Table(name = "customer_identities")
public class CustomerIdentity {
    public enum Status { PENDING_VERIFICATION, ACTIVE, SUSPENDED, CLOSED }

    @Id private UUID id;
    @Column(name = "tenant_id", nullable = false) private String tenantId;
    @Column(nullable = false) private String email;
    @Column(name = "display_name", nullable = false) private String displayName;
    @Column(name = "password_hash", nullable = false) private String passwordHash;
    @Enumerated(EnumType.STRING) @Column(nullable = false) private Status status;
    @Column(name = "email_verified_at") private Instant emailVerifiedAt;
    @Column(name = "created_at", nullable = false) private Instant createdAt;
    @Column(name = "updated_at", nullable = false) private Instant updatedAt;
    @Column(name = "token_version", nullable = false) private long tokenVersion;
    @Version @Column(nullable = false) private long revision;

    protected CustomerIdentity() {}

    public CustomerIdentity(String tenantId, String email, String displayName,
                            String passwordHash, Instant now) {
        this.id = UUID.randomUUID();
        this.tenantId = tenantId;
        this.email = email;
        this.displayName = displayName;
        this.passwordHash = passwordHash;
        this.status = Status.PENDING_VERIFICATION;
        this.createdAt = now;
        this.updatedAt = now;
        this.tokenVersion = 1;
    }

    public void verify(Instant now) {
        if (status != Status.PENDING_VERIFICATION) {
            throw new IllegalStateException("customer is not pending verification");
        }
        status = Status.ACTIVE;
        emailVerifiedAt = now;
        updatedAt = now;
    }

    public void recoverCredential(String encodedPassword, Instant now) {
        if (status != Status.ACTIVE) {
            throw new IllegalStateException("only an active customer can recover credentials");
        }
        passwordHash = encodedPassword;
        tokenVersion++;
        updatedAt = now;
    }

    public void suspend(Instant now) {
        if (status != Status.ACTIVE) throw new IllegalStateException("only an active customer can be suspended");
        status = Status.SUSPENDED;
        tokenVersion++;
        updatedAt = now;
    }

    public void reactivate(Instant now) {
        if (status != Status.SUSPENDED) throw new IllegalStateException("customer is not suspended");
        status = Status.ACTIVE;
        tokenVersion++;
        updatedAt = now;
    }

    public UUID getId() { return id; }
    public String getTenantId() { return tenantId; }
    public String getEmail() { return email; }
    public String getDisplayName() { return displayName; }
    public String getPasswordHash() { return passwordHash; }
    public Status getStatus() { return status; }
    public Instant getEmailVerifiedAt() { return emailVerifiedAt; }
    public Instant getCreatedAt() { return createdAt; }
    public Instant getUpdatedAt() { return updatedAt; }
    public long getTokenVersion() { return tokenVersion; }
    public long getRevision() { return revision; }
}
