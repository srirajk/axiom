package com.openwolf.iam.authority.federation;

import com.openwolf.iam.authority.lifecycle.WorkloadLifecycleService;
import com.openwolf.iam.entity.AgentWorkloadIdentity;
import com.openwolf.iam.exception.EntityNotFoundException;
import com.openwolf.iam.exception.ResourceConflictException;
import com.openwolf.iam.repository.AgentWorkloadIdentityRepository;
import com.openwolf.iam.service.AuditService;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.dao.DuplicateKeyException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.sql.Timestamp;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

/**
 * Phase 3.12 workload federation: an external (profile, issuer, subject) is bound by an administrator to exactly one
 * Agent workload. A verified assertion authenticates that workload's OAuth client — nothing more. It cannot name a
 * human, select another workload, or carry any authority: human authority still needs an Axiom-issued subject token
 * addressed to the workload. Assertions are short-lived, audience-bound to this Axiom and single-use.
 */
@Service
public class WorkloadFederationService {
    public record BindingView(UUID id, UUID agentWorkloadId, String providerProfile, String issuer, String subject,
                              String status, Instant createdAt, Instant revokedAt) {}

    private final JdbcTemplate jdbc;
    private final AgentWorkloadIdentityRepository workloads;
    private final WorkloadLifecycleService lifecycle;
    private final WorkloadAssertionVerifier verifier;
    private final AuditService audit;
    private final Clock clock = Clock.systemUTC();
    private final String audience;
    private final Duration maxLifetime;

    public WorkloadFederationService(JdbcTemplate jdbc, AgentWorkloadIdentityRepository workloads,
                                     WorkloadLifecycleService lifecycle, WorkloadAssertionVerifier verifier,
                                     AuditService audit,
                                     @Value("${spring.security.oauth2.authorizationserver.issuer:http://localhost:8084}") String issuer,
                                     @Value("${iam.workload-federation.max-assertion-lifetime:PT5M}") Duration maxLifetime) {
        this.jdbc = jdbc; this.workloads = workloads; this.lifecycle = lifecycle; this.verifier = verifier;
        this.audit = audit; this.audience = issuer + "/oauth/token"; this.maxLifetime = maxLifetime;
    }

    /** The audience every federated assertion must name: this Axiom's token endpoint. */
    public String audience() { return audience; }

    @Transactional
    public BindingView bind(String tenantId, UUID workloadId, String profile, String issuer, String subject, String actor) {
        AgentWorkloadIdentity workload = workloads.findByTenantIdAndId(tenantId, workloadId)
                .filter(lifecycle::usable)
                .orElseThrow(() -> new EntityNotFoundException("active agent workload identity not found"));
        if (profile == null || !profile.matches("[a-z][a-z0-9._-]{1,63}") || issuer == null || issuer.isBlank()
                || subject == null || subject.isBlank() || issuer.length() > 512 || subject.length() > 512) {
            throw new IllegalArgumentException("federation binding is malformed");
        }
        UUID id = UUID.randomUUID();
        Instant now = clock.instant();
        try {
            jdbc.update("INSERT INTO workload_federation_bindings (id, tenant_id, agent_workload_id, provider_profile, "
                    + "issuer, subject, status, created_at) VALUES (?, ?, ?, ?, ?, ?, 'ACTIVE', ?)", id, tenantId,
                    workload.getId(), profile, issuer.strip(), subject.strip(), Timestamp.from(now));
        } catch (DuplicateKeyException taken) {
            throw new ResourceConflictException("this external identity is already bound to a workload");
        }
        audit.logRequired(tenantId, actor, "WORKLOAD_FEDERATION_BOUND", "agent_workload_identity", workloadId.toString(),
                null, Map.of("binding_id", id.toString(), "profile", profile, "issuer", issuer.strip(),
                        "subject", subject.strip()), workloadId.toString());
        return get(id);
    }

    @Transactional
    public BindingView revoke(String tenantId, UUID workloadId, UUID bindingId, String actor) {
        int changed = jdbc.update("UPDATE workload_federation_bindings SET status = 'REVOKED', revoked_at = ? "
                + "WHERE id = ? AND tenant_id = ? AND agent_workload_id = ? AND status = 'ACTIVE'",
                Timestamp.from(clock.instant()), bindingId, tenantId, workloadId);
        if (changed == 1) {
            audit.logRequired(tenantId, actor, "WORKLOAD_FEDERATION_REVOKED", "agent_workload_identity",
                    workloadId.toString(), null, Map.of("binding_id", bindingId.toString()), workloadId.toString());
        }
        return get(bindingId);
    }

    @Transactional(readOnly = true)
    public List<BindingView> list(String tenantId, UUID workloadId) {
        return jdbc.query("SELECT * FROM workload_federation_bindings WHERE tenant_id = ? AND agent_workload_id = ? "
                + "ORDER BY created_at", (rs, i) -> view(rs), tenantId, workloadId);
    }

    /**
     * Authenticates {@code clientId} with a federated assertion; empty means "not authenticated" (the caller maps it
     * to {@code invalid_client} without detail). Replay rows are written in this transaction.
     */
    @Transactional
    public Optional<AgentWorkloadIdentity> authenticate(String clientId, String profile, String assertion) {
        if (clientId == null || profile == null || assertion == null || assertion.length() > 8192) return Optional.empty();
        WorkloadAssertionVerifier.Verified verified;
        try {
            verified = verifier.verify(profile, assertion);
        } catch (RuntimeException rejected) {
            return Optional.empty();
        }
        Instant now = clock.instant();
        if (verified == null || verified.jti() == null || verified.jti().isBlank() || verified.expiresAt() == null
                || verified.issuedAt() == null || !audience.equals(verified.audience())
                || !verified.expiresAt().isAfter(now) || verified.issuedAt().isAfter(now.plusSeconds(30))
                || Duration.between(verified.issuedAt(), verified.expiresAt()).compareTo(maxLifetime) > 0) {
            return Optional.empty();
        }
        List<UUID> bound = jdbc.queryForList("SELECT agent_workload_id FROM workload_federation_bindings WHERE "
                + "provider_profile = ? AND issuer = ? AND subject = ? AND status = 'ACTIVE'", UUID.class, profile,
                verified.issuer(), verified.subject());
        if (bound.size() != 1) return Optional.empty();
        Optional<AgentWorkloadIdentity> workload = workloads.findById(bound.getFirst())
                .filter(lifecycle::usable).filter(w -> w.getOauthClientId().equals(clientId));
        if (workload.isEmpty()) return Optional.empty();
        int fresh = jdbc.update("INSERT INTO workload_assertion_replays (provider_profile, issuer, jti, expires_at) "
                + "VALUES (?, ?, ?, ?) ON CONFLICT DO NOTHING", profile, verified.issuer(), verified.jti(),
                Timestamp.from(verified.expiresAt()));
        return fresh == 1 ? workload : Optional.empty();
    }

    private BindingView get(UUID id) {
        return jdbc.queryForObject("SELECT * FROM workload_federation_bindings WHERE id = ?", (rs, i) -> view(rs), id);
    }

    private static BindingView view(java.sql.ResultSet rs) throws java.sql.SQLException {
        Timestamp revoked = rs.getTimestamp("revoked_at");
        return new BindingView(rs.getObject("id", UUID.class), rs.getObject("agent_workload_id", UUID.class),
                rs.getString("provider_profile"), rs.getString("issuer"), rs.getString("subject"), rs.getString("status"),
                rs.getTimestamp("created_at").toInstant(), revoked == null ? null : revoked.toInstant());
    }
}
