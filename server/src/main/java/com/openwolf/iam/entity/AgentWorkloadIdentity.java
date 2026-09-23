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
@Table(name = "agent_workload_identities")
public class AgentWorkloadIdentity {
    public enum Status { ACTIVE, REVOKED }

    @Id private UUID id;
    @Column(name = "tenant_id", nullable = false) private String tenantId;
    @Column(name = "workload_ref", nullable = false) private String workloadRef;
    @Column(nullable = false) private String name;
    @Column(name = "oauth_client_id", nullable = false) private String oauthClientId;
    @Enumerated(EnumType.STRING) @Column(nullable = false) private Status status;
    @Column(name = "created_at", nullable = false) private Instant createdAt;
    @Column(name = "revoked_at") private Instant revokedAt;
    @Version @Column(nullable = false) private long revision;

    protected AgentWorkloadIdentity() {}

    public AgentWorkloadIdentity(String tenantId, String workloadRef, String name,
                                 String oauthClientId, Instant now) {
        this.id = UUID.randomUUID();
        this.tenantId = tenantId;
        this.workloadRef = workloadRef;
        this.name = name;
        this.oauthClientId = oauthClientId;
        this.status = Status.ACTIVE;
        this.createdAt = now;
    }

    public void revoke(Instant now) {
        if (status == Status.REVOKED) return;
        status = Status.REVOKED;
        revokedAt = now;
    }

    public UUID getId() { return id; }
    public String getTenantId() { return tenantId; }
    public String getWorkloadRef() { return workloadRef; }
    public String getName() { return name; }
    public String getOauthClientId() { return oauthClientId; }
    public Status getStatus() { return status; }
    public Instant getCreatedAt() { return createdAt; }
    public Instant getRevokedAt() { return revokedAt; }
    public long getRevision() { return revision; }
}
