package com.openwolf.iam.authority.lifecycle;

import com.openwolf.iam.entity.AgentWorkloadIdentity;
import com.openwolf.iam.entity.CustomerDelegationGrant;
import com.openwolf.iam.exception.EntityNotFoundException;
import com.openwolf.iam.exception.ResourceConflictException;
import com.openwolf.iam.repository.AgentWorkloadIdentityRepository;
import com.openwolf.iam.repository.CustomerDelegationGrantRepository;
import com.openwolf.iam.service.AuditService;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Clock;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * Phase 3.10/3.15 workload identity lifecycle. A workload may be given explicit ownership — a team (directory group)
 * and one accountable principal who is an active member of it. Once assigned, ownership is enforced on every use:
 * if the team is deleted or the accountable principal leaves the team or is disabled, the workload carries no
 * authority until ownership is reassigned. Owner departure (identity disable) also suspends the workload durably.
 * Retirement is terminal and keeps all history. Nothing infers a team identity from a service credential: teams own
 * workloads, they never act as token subjects (decision D-8).
 */
@Service
public class WorkloadLifecycleService {
    public enum ReviewDecision { KEEP, SUSPEND, RETIRE }

    public record WorkloadView(UUID id, String workloadRef, String oauthClientId, AgentWorkloadIdentity.Status status,
                               String suspensionReason, Instant suspendedAt, Instant retiredAt, UUID ownerTeamId,
                               String accountablePrincipalId, boolean ownershipValid, Instant lastReviewedAt,
                               long revision) {}

    private final AgentWorkloadIdentityRepository workloads;
    private final CustomerDelegationGrantRepository delegationGrants;
    private final JdbcTemplate jdbc;
    private final AuditService audit;
    private final com.openwolf.iam.repository.PrincipalRepository principals;
    private final Clock clock = Clock.systemUTC();

    public WorkloadLifecycleService(AgentWorkloadIdentityRepository workloads,
                                    CustomerDelegationGrantRepository delegationGrants, JdbcTemplate jdbc,
                                    AuditService audit, com.openwolf.iam.repository.PrincipalRepository principals) {
        this.workloads = workloads; this.delegationGrants = delegationGrants; this.jdbc = jdbc; this.audit = audit;
        this.principals = principals;
    }

    /**
     * Use-time rule shared by every authority path: an ACTIVE workload whose assigned ownership (if any) is still
     * valid. Workloads without assigned ownership keep their Phase 1 behaviour.
     */
    public boolean usable(AgentWorkloadIdentity workload) {
        return workload.getStatus() == AgentWorkloadIdentity.Status.ACTIVE
                && (!workload.ownershipAssigned() || ownershipValid(workload));
    }

    /**
     * Phase 3.15: may this OAuth client obtain a token as itself? Clients that are not an Agent workload's identity
     * (ordinary service clients, brokers) are unaffected; an Agent's client may only while its workload is usable.
     * A client backs at most one workload (unique per tenant, and a client belongs to one tenant).
     */
    @Transactional(readOnly = true)
    public boolean clientMayIssue(String clientId) {
        return workloads.findByOauthClientId(clientId).map(this::usable).orElse(true);
    }

    public boolean ownershipValid(AgentWorkloadIdentity workload) {
        if (workload.getOwnerTeamId() == null || workload.getAccountablePrincipalId() == null) return false;
        Integer valid = jdbc.queryForObject("SELECT count(*) FROM groups g JOIN group_members m ON m.group_id = g.id "
                + "JOIN principals p ON p.id = m.principal_id WHERE g.id = ? AND g.tenant_id = ? AND p.id = ? "
                + "AND p.tenant_id = ? AND p.is_active", Integer.class, workload.getOwnerTeamId(), workload.getTenantId(),
                workload.getAccountablePrincipalId(), workload.getTenantId());
        return valid != null && valid == 1;
    }

    @Transactional
    public WorkloadView assignOwnership(String tenantId, UUID workloadId, UUID teamId, String accountable, String actor) {
        AgentWorkloadIdentity workload = workload(tenantId, workloadId);
        if (terminal(workload)) throw new ResourceConflictException("workload is no longer manageable");
        workload.assignOwnership(teamId, accountable, clock.instant());
        if (!ownershipValid(workload)) {
            throw new IllegalArgumentException("accountable principal must be an active member of the owning team");
        }
        audit.logRequired(tenantId, actor, "AGENT_WORKLOAD_OWNERSHIP_ASSIGNED", "agent_workload_identity",
                workloadId.toString(), null, Map.of("team_id", teamId.toString(), "accountable_principal", accountable),
                workloadId.toString());
        return view(workload);
    }

    @Transactional
    public WorkloadView suspend(String tenantId, UUID workloadId, String reason, String actor) {
        AgentWorkloadIdentity workload = workload(tenantId, workloadId);
        String why = label(reason, "suspended");
        if (workload.suspend(why, clock.instant())) {
            audit.logRequired(tenantId, actor, "AGENT_WORKLOAD_SUSPENDED", "agent_workload_identity",
                    workloadId.toString(), null, Map.of("reason", why), workloadId.toString());
        } else if (workload.getStatus() != AgentWorkloadIdentity.Status.SUSPENDED) {
            throw new ResourceConflictException("workload is not active");
        }
        return view(workload);
    }

    /** Reactivation requires valid ownership when ownership was ever assigned (reassign first after departure). */
    @Transactional
    public WorkloadView reactivate(String tenantId, UUID workloadId, String actor) {
        AgentWorkloadIdentity workload = workload(tenantId, workloadId);
        if (workload.ownershipAssigned() && !ownershipValid(workload)) {
            throw new ResourceConflictException("reassign valid ownership before reactivating");
        }
        if (workload.reactivate()) {
            audit.logRequired(tenantId, actor, "AGENT_WORKLOAD_REACTIVATED", "agent_workload_identity",
                    workloadId.toString(), null, Map.of("status", "ACTIVE"), workloadId.toString());
        } else if (workload.getStatus() != AgentWorkloadIdentity.Status.ACTIVE) {
            throw new ResourceConflictException("workload is not suspended");
        }
        return view(workload);
    }

    /** Terminal retirement: customer consent for the workload is withdrawn; audit history is retained. */
    @Transactional
    public WorkloadView retire(String tenantId, UUID workloadId, String reason, String actor) {
        AgentWorkloadIdentity workload = workload(tenantId, workloadId);
        Instant now = clock.instant();
        String why = label(reason, "retired");
        if (workload.retire(now)) {
            List<CustomerDelegationGrant> grants = delegationGrants.findByTenantIdAndAgentWorkloadIdAndStatus(tenantId,
                    workloadId, CustomerDelegationGrant.Status.ACTIVE);
            grants.forEach(g -> g.revoke("agent workload retired", now));
            int standing = jdbc.update("UPDATE standing_grants SET status = 'REVOKED', version = version + 1, "
                    + "revoked_at = ?, revocation_reason = 'agent workload retired' WHERE tenant_id = ? "
                    + "AND agent_workload_id = ? AND status <> 'REVOKED'", java.sql.Timestamp.from(now), tenantId, workloadId);
            audit.logRequired(tenantId, actor, "AGENT_WORKLOAD_RETIRED", "agent_workload_identity",
                    workloadId.toString(), null, Map.of("reason", why, "revoked_delegation_grants", grants.size(),
                            "revoked_standing_grants", standing), workloadId.toString());
        }
        return view(workload);
    }

    @Transactional
    public WorkloadView review(String tenantId, UUID workloadId, ReviewDecision decision, String notes, String reviewer) {
        AgentWorkloadIdentity workload = workload(tenantId, workloadId);
        if (terminal(workload)) throw new ResourceConflictException("workload is no longer manageable");
        boolean ownership = workload.ownershipAssigned() && ownershipValid(workload);
        Instant now = clock.instant();
        jdbc.update("INSERT INTO workload_access_reviews (id, tenant_id, agent_workload_id, reviewer, decision, notes, "
                + "ownership_valid, reviewed_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)", UUID.randomUUID(), tenantId, workloadId,
                reviewer, decision.name(), notes == null ? null : label(notes, null), ownership, java.sql.Timestamp.from(now));
        workload.reviewed(now);
        audit.logRequired(tenantId, reviewer, "AGENT_WORKLOAD_ACCESS_REVIEWED", "agent_workload_identity",
                workloadId.toString(), null, Map.of("decision", decision.name(), "ownership_valid", ownership),
                workloadId.toString());
        return switch (decision) {
            case KEEP -> {
                if (!ownership) throw new ResourceConflictException("a workload without valid ownership cannot be kept");
                yield view(workload);
            }
            case SUSPEND -> suspend(tenantId, workloadId, "access review", reviewer);
            case RETIRE -> retire(tenantId, workloadId, "access review", reviewer);
        };
    }

    /**
     * Identity-disable hook: suspends every ACTIVE workload for which the departed principal was accountable, in the
     * disabling transaction. Ignored when the principal is still active (session sweeps also run on re-enable).
     */
    @Transactional
    public int onPrincipalDisabled(String tenantId, String principalId) {
        // Read through JPA: the disabling transaction's pending change is visible here, unlike a raw JDBC read.
        Boolean active = principals.findById(principalId).filter(p -> tenantId.equals(p.getTenantId()))
                .map(com.openwolf.iam.entity.Principal::isActive).orElse(null);
        if (active == null || active) return 0;
        int suspended = 0;
        for (AgentWorkloadIdentity workload : workloads.findByTenantIdOrderByCreatedAtAsc(tenantId)) {
            if (principalId.equals(workload.getAccountablePrincipalId())
                    && workload.suspend("accountable owner departed", clock.instant())) {
                suspended++;
                audit.logRequired(tenantId, "system", "AGENT_WORKLOAD_SUSPENDED", "agent_workload_identity",
                        workload.getId().toString(), null, Map.of("reason", "accountable owner departed",
                                "principal", principalId), workload.getId().toString());
            }
        }
        return suspended;
    }

    @Transactional(readOnly = true)
    public List<WorkloadView> list(String tenantId) {
        return workloads.findByTenantIdOrderByCreatedAtAsc(tenantId).stream().map(this::view).toList();
    }

    private AgentWorkloadIdentity workload(String tenantId, UUID id) {
        return workloads.findByTenantIdAndId(tenantId, id)
                .orElseThrow(() -> new EntityNotFoundException("agent workload identity not found"));
    }

    private static boolean terminal(AgentWorkloadIdentity w) {
        return w.getStatus() == AgentWorkloadIdentity.Status.RETIRED || w.getStatus() == AgentWorkloadIdentity.Status.REVOKED;
    }

    private WorkloadView view(AgentWorkloadIdentity w) {
        return new WorkloadView(w.getId(), w.getWorkloadRef(), w.getOauthClientId(), w.getStatus(),
                w.getSuspensionReason(), w.getSuspendedAt(), w.getRetiredAt(), w.getOwnerTeamId(),
                w.getAccountablePrincipalId(), w.ownershipAssigned() && ownershipValid(w), w.getLastReviewedAt(),
                w.getRevision());
    }

    private static String label(String value, String fallback) {
        if (value == null || value.isBlank()) return fallback;
        String v = value.strip();
        return v.length() > 200 ? v.substring(0, 200) : v;
    }
}
