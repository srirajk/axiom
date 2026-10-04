package com.openwolf.iam.authority.task;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

import java.time.Instant;
import java.util.UUID;

/**
 * Phase 3.4 durable task: a workflow's handle on the authority it runs under (one standing grant or invocation
 * context, at a recorded version). It holds no token and no secret. Ending a task is permanent.
 */
@Entity
@Table(name = "durable_tasks")
public class DurableTask {
    public enum Status { ACTIVE, CANCELLED, COMPLETED }
    public enum AuthorityType { STANDING_GRANT, INVOCATION_CONTEXT }

    @Id private UUID id;
    @Column(name = "tenant_id", nullable = false) private String tenantId;
    @Column(name = "agent_workload_id", nullable = false) private UUID agentWorkloadId;
    @Column(name = "owner_subject", nullable = false) private String ownerSubject;
    @Enumerated(EnumType.STRING) @Column(name = "authority_type", nullable = false) private AuthorityType authorityType;
    @Column(name = "authority_id", nullable = false) private UUID authorityId;
    @Column(name = "authority_version", nullable = false) private long authorityVersion;
    @Column(name = "task_ref") private String taskRef;
    @Column(name = "callback_provider") private String callbackProvider;
    @Enumerated(EnumType.STRING) @Column(nullable = false) private Status status;
    @Column(nullable = false) private long version;
    @Column(name = "resume_count", nullable = false) private int resumeCount;
    @Column(name = "callback_count", nullable = false) private int callbackCount;
    @Column(name = "last_resumed_at") private Instant lastResumedAt;
    @Column(name = "last_callback_at") private Instant lastCallbackAt;
    @Column(name = "ended_at") private Instant endedAt;
    @Column(name = "end_reason") private String endReason;
    @Column(name = "created_at", nullable = false) private Instant createdAt;

    protected DurableTask() {}

    DurableTask(String tenantId, UUID agentWorkloadId, String ownerSubject, AuthorityType type, UUID authorityId,
                long authorityVersion, String taskRef, String callbackProvider, Instant now) {
        this.id = UUID.randomUUID();
        this.tenantId = tenantId;
        this.agentWorkloadId = agentWorkloadId;
        this.ownerSubject = ownerSubject;
        this.authorityType = type;
        this.authorityId = authorityId;
        this.authorityVersion = authorityVersion;
        this.taskRef = taskRef;
        this.callbackProvider = callbackProvider;
        this.status = Status.ACTIVE;
        this.version = 1;
        this.createdAt = now;
    }

    void resumed(Instant now) {
        resumeCount++;
        lastResumedAt = now;
    }

    void callback(Instant now) {
        callbackCount++;
        lastCallbackAt = now;
    }

    boolean end(Status terminal, String reason, Instant now) {
        if (status != Status.ACTIVE) return false;
        status = terminal;
        version++;
        endedAt = now;
        endReason = reason;
        return true;
    }

    public UUID getId() { return id; }
    public String getTenantId() { return tenantId; }
    public UUID getAgentWorkloadId() { return agentWorkloadId; }
    public String getOwnerSubject() { return ownerSubject; }
    public AuthorityType getAuthorityType() { return authorityType; }
    public UUID getAuthorityId() { return authorityId; }
    public long getAuthorityVersion() { return authorityVersion; }
    public String getTaskRef() { return taskRef; }
    public String getCallbackProvider() { return callbackProvider; }
    public Status getStatus() { return status; }
    public long getVersion() { return version; }
    public int getResumeCount() { return resumeCount; }
    public int getCallbackCount() { return callbackCount; }
    public Instant getLastResumedAt() { return lastResumedAt; }
    public Instant getLastCallbackAt() { return lastCallbackAt; }
    public Instant getEndedAt() { return endedAt; }
    public String getEndReason() { return endReason; }
    public Instant getCreatedAt() { return createdAt; }
}
