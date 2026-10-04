package com.openwolf.iam.authority.task;

import com.openwolf.iam.authority.standing.StandingGrantService;
import com.openwolf.iam.entity.AgentWorkloadIdentity;
import com.openwolf.iam.exception.EntityNotFoundException;
import com.openwolf.iam.exception.ResourceConflictException;
import com.openwolf.iam.invocation.InvocationContextService;
import com.openwolf.iam.repository.AgentWorkloadIdentityRepository;
import com.openwolf.iam.service.AuditService;
import com.openwolf.iam.service.TenantApplicationService;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Clock;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;

/**
 * Phase 3.4 durable tasks. A task records which authority (standing grant or invocation context) it runs under and
 * that authority's version. Every resume re-reads the authority: withdrawn, expired, re-versioned or otherwise
 * non-current authority refuses the resume, and an ended task never resumes — including after a restart, because the
 * state lives only in PostgreSQL. Tasks hold identifiers and versions, never tokens or secrets.
 */
@Service
public class DurableTaskService implements StandingGrantService.TaskBinding {
    public record TaskView(UUID id, UUID agentWorkloadId, String ownerSubject, DurableTask.AuthorityType authorityType,
                           UUID authorityId, long authorityVersion, String taskRef, String callbackProvider,
                           DurableTask.Status status, long version, int resumeCount, int callbackCount,
                           Instant lastResumedAt, Instant lastCallbackAt, Instant endedAt, String endReason,
                           Instant createdAt) {}

    private final DurableTaskRepository tasks;
    private final AgentWorkloadIdentityRepository workloads;
    private final TenantApplicationService applications;
    private final StandingGrantService standingGrants;
    private final InvocationContextService contexts;
    private final AuditService audit;
    private final Clock clock = Clock.systemUTC();

    public DurableTaskService(DurableTaskRepository tasks, AgentWorkloadIdentityRepository workloads,
                              TenantApplicationService applications, StandingGrantService standingGrants,
                              InvocationContextService contexts, AuditService audit) {
        this.tasks = tasks; this.workloads = workloads; this.applications = applications;
        this.standingGrants = standingGrants; this.contexts = contexts; this.audit = audit;
    }

    @Transactional
    public TaskView create(String tenantId, String clientId, DurableTask.AuthorityType type, UUID authorityId,
                           String taskRef, String callbackProvider) {
        AgentWorkloadIdentity workload = callerWorkload(tenantId, clientId);
        String ref = label(taskRef);
        String provider = label(callbackProvider);
        long version;
        String owner;
        if (type == DurableTask.AuthorityType.STANDING_GRANT) {
            version = standingGrants.currentVersion(tenantId, authorityId, workload.getId());
            owner = standingGrants.ownerOf(tenantId, authorityId);
        } else {
            String audience = applications.activeAuthority(clientId).map(TenantApplicationService.ClientAuthority::audience)
                    .orElseThrow(() -> new AccessDeniedException("caller client is not active"));
            InvocationContextService.TaskAuthority authority = contexts.taskAuthority(tenantId, authorityId, audience);
            version = authority.version();
            owner = authority.originatingSubject();
        }
        if (ref != null) {
            var existing = tasks.findByTenantIdAndAgentWorkloadIdAndTaskRef(tenantId, workload.getId(), ref);
            if (existing.isPresent()) {
                DurableTask t = existing.get();
                if (t.getAuthorityType() != type || !t.getAuthorityId().equals(authorityId)) {
                    throw new ResourceConflictException("task reference already bound to other authority");
                }
                return view(t);
            }
        }
        DurableTask task = tasks.saveAndFlush(new DurableTask(tenantId, workload.getId(), owner, type, authorityId,
                version, ref, provider, clock.instant()));
        audit.logRequired(tenantId, clientId, "DURABLE_TASK_CREATED", "durable_task", task.getId().toString(), null,
                snapshot(task), task.getAuthorityId().toString());
        return view(task);
    }

    @Transactional(readOnly = true)
    public TaskView get(String tenantId, String clientId, UUID taskId) {
        DurableTask task = owned(tenantId, taskId, callerWorkload(tenantId, clientId));
        return view(task);
    }

    /** Resume re-checks the task and its governing authority against current state. */
    @Transactional
    public TaskView resume(String tenantId, String clientId, UUID taskId) {
        AgentWorkloadIdentity workload = callerWorkload(tenantId, clientId);
        DurableTask task = tasks.lock(taskId, tenantId).filter(t -> t.getAgentWorkloadId().equals(workload.getId()))
                .orElseThrow(() -> new EntityNotFoundException("task not found"));
        if (task.getStatus() != DurableTask.Status.ACTIVE) throw new ResourceConflictException("task is not active");
        long current;
        if (task.getAuthorityType() == DurableTask.AuthorityType.STANDING_GRANT) {
            current = standingGrants.currentVersion(tenantId, task.getAuthorityId(), workload.getId());
        } else {
            String audience = applications.activeAuthority(clientId).map(TenantApplicationService.ClientAuthority::audience)
                    .orElseThrow(() -> new AccessDeniedException("caller client is not active"));
            current = contexts.taskAuthority(tenantId, task.getAuthorityId(), audience).version();
        }
        if (current != task.getAuthorityVersion()) throw new AccessDeniedException("task authority has changed");
        task.resumed(clock.instant());
        audit.logRequired(tenantId, clientId, "DURABLE_TASK_RESUMED", "durable_task", taskId.toString(), null,
                Map.of("authority_type", task.getAuthorityType().name(), "authority_id", task.getAuthorityId().toString(),
                        "authority_version", current, "resume_count", task.getResumeCount()), taskId.toString());
        return view(task);
    }

    @Transactional
    public TaskView endByWorkload(String tenantId, String clientId, UUID taskId, DurableTask.Status terminal,
                                  String reason) {
        AgentWorkloadIdentity workload = callerWorkload(tenantId, clientId);
        DurableTask task = tasks.lock(taskId, tenantId).filter(t -> t.getAgentWorkloadId().equals(workload.getId()))
                .orElseThrow(() -> new EntityNotFoundException("task not found"));
        return end(task, terminal, reason, clientId);
    }

    /** The owner (the human the work runs for) can always cancel it. */
    @Transactional
    public TaskView cancelByOwner(String tenantId, String owner, UUID taskId, String reason) {
        DurableTask task = tasks.lock(taskId, tenantId).filter(t -> t.getOwnerSubject().equals(owner))
                .orElseThrow(() -> new EntityNotFoundException("task not found"));
        return end(task, DurableTask.Status.CANCELLED, reason, owner);
    }

    @Transactional
    public TaskView cancelByAdministrator(String tenantId, UUID taskId, String reason, String actor) {
        DurableTask task = tasks.lock(taskId, tenantId).orElseThrow(() -> new EntityNotFoundException("task not found"));
        return end(task, DurableTask.Status.CANCELLED, reason, actor);
    }

    private TaskView end(DurableTask task, DurableTask.Status terminal, String reason, String actor) {
        if (terminal == DurableTask.Status.ACTIVE) throw new IllegalArgumentException("not a terminal status");
        String why = label(reason == null || reason.isBlank() ? terminal.name().toLowerCase() : reason);
        if (task.end(terminal, why, clock.instant())) {
            audit.logRequired(task.getTenantId(), actor, "DURABLE_TASK_" + terminal.name(), "durable_task",
                    task.getId().toString(), null, Map.of("reason", why, "version", task.getVersion()),
                    task.getId().toString());
        } else if (task.getStatus() != terminal) {
            throw new ResourceConflictException("task already ended as " + task.getStatus());
        }
        return view(task);
    }

    @Override
    @Transactional(readOnly = true)
    public boolean boundToStandingGrant(String tenantId, UUID taskId, UUID grantId, long grantVersion, UUID workloadId) {
        return tasks.findByTenantIdAndId(tenantId, taskId)
                .filter(t -> t.getStatus() == DurableTask.Status.ACTIVE)
                .filter(t -> t.getAuthorityType() == DurableTask.AuthorityType.STANDING_GRANT)
                .filter(t -> t.getAuthorityId().equals(grantId) && t.getAuthorityVersion() == grantVersion)
                .filter(t -> t.getAgentWorkloadId().equals(workloadId))
                .isPresent();
    }


    private com.openwolf.iam.authority.lifecycle.WorkloadLifecycleService lifecycle;

    @org.springframework.beans.factory.annotation.Autowired(required = false)
    void setLifecycle(@org.springframework.context.annotation.Lazy com.openwolf.iam.authority.lifecycle.WorkloadLifecycleService lifecycle) {
        this.lifecycle = lifecycle;
    }

    /** ACTIVE and, once ownership is assigned, still validly owned (Phase 3.10/3.15). */
    private boolean usable(com.openwolf.iam.entity.AgentWorkloadIdentity workload) {
        return lifecycle == null ? workload.getStatus() == com.openwolf.iam.entity.AgentWorkloadIdentity.Status.ACTIVE
                : lifecycle.usable(workload);
    }

    private AgentWorkloadIdentity callerWorkload(String tenantId, String clientId) {
        return workloads.findByOauthClientId(clientId)
                .filter(w -> w.getTenantId().equals(tenantId))
                .filter(this::usable)
                .orElseThrow(() -> new AccessDeniedException("caller is not an active Agent workload"));
    }

    private DurableTask owned(String tenantId, UUID taskId, AgentWorkloadIdentity workload) {
        return tasks.findByTenantIdAndId(tenantId, taskId).filter(t -> t.getAgentWorkloadId().equals(workload.getId()))
                .orElseThrow(() -> new EntityNotFoundException("task not found"));
    }

    static TaskView view(DurableTask t) {
        return new TaskView(t.getId(), t.getAgentWorkloadId(), t.getOwnerSubject(), t.getAuthorityType(),
                t.getAuthorityId(), t.getAuthorityVersion(), t.getTaskRef(), t.getCallbackProvider(), t.getStatus(),
                t.getVersion(), t.getResumeCount(), t.getCallbackCount(), t.getLastResumedAt(), t.getLastCallbackAt(),
                t.getEndedAt(), t.getEndReason(), t.getCreatedAt());
    }

    private static Map<String, Object> snapshot(DurableTask t) {
        Map<String, Object> s = new LinkedHashMap<>();
        s.put("task_id", t.getId().toString());
        s.put("agent_workload_id", t.getAgentWorkloadId().toString());
        s.put("owner", t.getOwnerSubject());
        s.put("authority_type", t.getAuthorityType().name());
        s.put("authority_id", t.getAuthorityId().toString());
        s.put("authority_version", t.getAuthorityVersion());
        if (t.getTaskRef() != null) s.put("task_ref", t.getTaskRef());
        if (t.getCallbackProvider() != null) s.put("callback_provider", t.getCallbackProvider());
        return s;
    }

    static String label(String value) {
        if (value == null) return null;
        String v = value.strip();
        if (v.isEmpty()) return null;
        if (!v.matches("[A-Za-z0-9][A-Za-z0-9._:/ -]{0,127}")) throw new IllegalArgumentException("malformed label");
        return v;
    }
}
