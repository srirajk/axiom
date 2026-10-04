package com.openwolf.iam.service;

import com.openwolf.iam.auth.ExecutionTenant;
import com.openwolf.iam.dto.IamSessionResponse;
import com.openwolf.iam.dto.RevokeIamSessionRequest;
import com.openwolf.iam.entity.IamSession;
import com.openwolf.iam.exception.EntityNotFoundException;
import com.openwolf.iam.exception.ResourceConflictException;
import com.openwolf.iam.repository.IamSessionRepository;
import com.openwolf.iam.repository.PrincipalRepository;
import com.openwolf.iam.repository.RecoveryOperatorRepository;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.security.core.Authentication;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.UUID;

@Service
@Transactional
public class IamSessionService {
    private static final Duration LAST_SEEN_WRITE_INTERVAL = Duration.ofSeconds(30);
    private final IamSessionRepository sessions;
    private final ExecutionTenant executionTenant;
    private final AuditService audit;
    private final RecoveryOperatorRepository recoveryOperators;
    private final PrincipalRepository principals;
    private final Clock clock;

    @Autowired
    public IamSessionService(IamSessionRepository sessions, ExecutionTenant executionTenant, AuditService audit,
                             RecoveryOperatorRepository recoveryOperators, PrincipalRepository principals) {
        this(sessions, executionTenant, audit, Clock.systemUTC(), recoveryOperators, principals);
    }

    IamSessionService(IamSessionRepository sessions, ExecutionTenant executionTenant, AuditService audit, Clock clock) {
        this(sessions, executionTenant, audit, clock, null, null);
    }

    IamSessionService(IamSessionRepository sessions, ExecutionTenant executionTenant, AuditService audit, Clock clock,
                      RecoveryOperatorRepository recoveryOperators) {
        this(sessions, executionTenant, audit, clock, recoveryOperators, null);
    }

    IamSessionService(IamSessionRepository sessions, ExecutionTenant executionTenant, AuditService audit, Clock clock,
                      RecoveryOperatorRepository recoveryOperators, PrincipalRepository principals) {
        this.sessions = sessions; this.executionTenant = executionTenant; this.audit = audit;
        this.clock = clock; this.recoveryOperators = recoveryOperators; this.principals = principals;
    }

    public UUID issue(String authorizationId, String tenantId, String principalId, UUID applicationId,
                      String clientId, Instant expiresAt) {
        UUID id = UUID.nameUUIDFromBytes(("axiom-session:" + authorizationId).getBytes(StandardCharsets.UTF_8));
        Instant now = clock.instant();
        IamSession existing = sessions.findById(id).orElse(null);
        if (existing != null) {
            if (!tenantId.equals(existing.getTenantId()) || !principalId.equals(existing.getPrincipalId())
                    || !clientId.equals(existing.getClientId())) throw new IllegalStateException("session binding conflict");
            if (existing.getStatus() != IamSession.Status.ACTIVE || !existing.getExpiresAt().isAfter(now)) {
                throw new IllegalStateException("session is no longer active");
            }
            touch(id, tenantId, now);
            return id;
        }
        sessions.save(new IamSession(id, tenantId, principalId, applicationId, clientId, now, expiresAt));
        return id;
    }

    /** Serializes workforce issuance with principal disable/re-enable and rejects inactive principals. */
    public UUID issueForWorkforce(String authorizationId, String tenantId, String principalId, UUID applicationId,
                                  String clientId, Instant expiresAt) {
        if (principals == null || principals.findByIdAndTenantIdForUpdate(principalId, tenantId)
                .map(principal -> !principal.isActive()).orElse(true)) {
            throw new DisabledException("Account is disabled or unavailable");
        }
        return issue(authorizationId, tenantId, principalId, applicationId, clientId, expiresAt);
    }

    public UUID issueRecovery(String tenantId, String principalId, Instant expiresAt,
                              UUID recoveryOperatorA, UUID recoveryOperatorB) {
        if (recoveryOperatorA.equals(recoveryOperatorB)) throw new IllegalArgumentException("distinct recovery operators are required");
        UUID id = UUID.randomUUID();
        sessions.save(new IamSession(id, tenantId, principalId, "recovery", clock.instant(), expiresAt,
                "identity-admin", recoveryOperatorA, recoveryOperatorB));
        return id;
    }

    @Transactional(readOnly = true)
    public Page<IamSessionResponse> list(String tenantId, String principalId, String clientId, IamSession.Status status,
                                         int page, int size) {
        requireTenantAdmin(tenantId);
        int boundedSize = Math.min(Math.max(size, 1), 100);
        return sessions.search(tenantId, principalId, clientId, status, PageRequest.of(Math.max(page, 0), boundedSize))
                .map(this::response);
    }

    @Transactional(readOnly = true)
    public List<IamSessionResponse> selfList(int page, int size) {
        String tenantId = executionTenant.require();
        String principalId = currentSubject();
        return listForPrincipal(tenantId, principalId, page, size);
    }

    @Transactional(readOnly = true)
    public List<IamSessionResponse> listForPrincipal(String tenantId, String principalId, int page, int size) {
        return sessions.search(tenantId, principalId, null, null, PageRequest.of(Math.max(page, 0), Math.min(Math.max(size, 1), 100)))
                .map(this::response).getContent();
    }

    public IamSessionResponse revoke(String tenantId, UUID id, RevokeIamSessionRequest request, HttpServletRequest httpRequest) {
        IamSession session = sessionForTenant(tenantId, id);
        requireRevision(session, request.expectedRevision());
        if (session.getStatus() == IamSession.Status.REVOKED) return response(session);
        IamSessionResponse before = response(session);
        session.revoke(); sessions.save(session);
        // Supported logout and administrative session revocation end every run the session started (Phase 2.9).
        if (invocationContexts != null) invocationContexts.revokeForRootSession(tenantId, id, "session revoked");
        IamSessionResponse after = response(session, session.getRevision() + 1);
        audit.logRequired(tenantId, audit.currentActor(), "REVOKE_SESSION", "session", id.toString(), before, after,
                httpRequest == null ? null : httpRequest.getHeader("X-Correlation-ID"));
        return after;
    }

    /** The durable session id Axiom binds to an OAuth authorization (deterministic; see {@link #issue}). */
    public static UUID sessionIdFor(String authorizationId) {
        return UUID.nameUUIDFromBytes(("axiom-session:" + authorizationId).getBytes(StandardCharsets.UTF_8));
    }

    /**
     * System revocation of the session bound to one OAuth authorization: OIDC logout, token revocation (RFC 7009),
     * a replayed authorization code, or removal of the authorization. Idempotent; returns true if it changed.
     */
    public boolean revokeForAuthorization(String tenantId, String authorizationId, String reason) {
        UUID id = sessionIdFor(authorizationId);
        IamSession session = sessions.findByIdAndTenantId(id, tenantId).orElse(null);
        if (session == null || session.getStatus() != IamSession.Status.ACTIVE) return false;
        session.revoke();
        sessions.save(session);
        if (invocationContexts != null) invocationContexts.revokeForRootSession(tenantId, id, reason);
        audit.logRequired(tenantId, "system", "REVOKE_SESSION", "session", id.toString(), null,
                java.util.Map.of("reason", reason, "client_id", session.getClientId()), id.toString());
        return true;
    }

    /** Ends every active session issued to one OAuth client (client or application disabled/revoked). */
    public int revokeAllForClient(String tenantId, String clientId, String reason) {
        List<IamSession> active = sessions.findActiveForClientForUpdate(tenantId, clientId, IamSession.Status.ACTIVE);
        for (IamSession session : active) {
            session.revoke();
            if (invocationContexts != null) invocationContexts.revokeForRootSession(tenantId, session.getId(), reason);
        }
        if (!active.isEmpty()) {
            audit.logRequired(tenantId, audit.currentActor(), "REVOKE_CLIENT_SESSIONS", "application_client", clientId,
                    null, java.util.Map.of("reason", reason, "revoked_sessions", active.size()), clientId);
        }
        return active.size();
    }

    /** Ends one principal's sessions issued to one client (e.g. a customer withdrawing an application's consent). */
    public int revokeAllForPrincipalAndClient(String tenantId, String principalId, String clientId, String reason) {
        List<IamSession> active = sessions.findActiveForPrincipalForUpdate(tenantId, principalId, IamSession.Status.ACTIVE)
                .stream().filter(session -> clientId.equals(session.getClientId())).toList();
        for (IamSession session : active) {
            session.revoke();
            if (invocationContexts != null) invocationContexts.revokeForRootSession(tenantId, session.getId(), reason);
        }
        if (!active.isEmpty()) {
            audit.logRequired(tenantId, principalId, "REVOKE_PRINCIPAL_CLIENT_SESSIONS", "application_client", clientId,
                    null, java.util.Map.of("reason", reason, "revoked_sessions", active.size()), clientId);
        }
        return active.size();
    }

    public IamSessionResponse selfRevoke(UUID id, RevokeIamSessionRequest request, HttpServletRequest requestContext) {
        String tenantId = executionTenant.require();
        IamSession session = sessionForTenant(tenantId, id);
        if (!currentSubject().equals(session.getPrincipalId())) throw EntityNotFoundException.forId("Session", id);
        return revoke(tenantId, id, request, requestContext);
    }

    @Transactional(readOnly = true)
    public boolean active(UUID id, String tenantId, Instant now) {
        return active(id, tenantId, now, false, null);
    }

    @Transactional(readOnly = true)
    public boolean active(UUID id, String tenantId, Instant now, boolean recoveryMarked, String recoveryScope) {
        IamSession session = sessions.findByIdAndTenantId(id, tenantId).orElse(null);
        if (session == null || session.getStatus() != IamSession.Status.ACTIVE || !session.getExpiresAt().isAfter(now)) return false;
        // Revocation closes normal disable paths; this live check also closes a login that
        // inserted a session just after the disable transaction scanned active sessions.
        if (principals != null && principals.findById(session.getPrincipalId())
                .map(principal -> !principal.getTenantId().equals(tenantId) || !principal.isActive())
                .orElse(false)) return false;
        if (!session.isRecoveryMarked()) return !recoveryMarked && recoveryScope == null;
        if (!recoveryMarked || !"identity-admin".equals(recoveryScope) || recoveryOperators == null) return false;
        return recoveryOperators.findByIdAndTenantId(session.getRecoveryOperatorA(), tenantId)
                .map(first -> first.getStatus() == com.openwolf.iam.entity.RecoveryOperator.Status.ACTIVE)
                .orElse(false)
                && recoveryOperators.findByIdAndTenantId(session.getRecoveryOperatorB(), tenantId)
                .map(second -> second.getStatus() == com.openwolf.iam.entity.RecoveryOperator.Status.ACTIVE)
                .orElse(false);
    }

    @Transactional
    public void touch(UUID id, String tenantId, Instant now) {
        // Session validity is checked separately. Bound last-seen write amplification
        // without extending token lifetime or changing the revocation decision.
        sessions.touch(id, tenantId, now, IamSession.Status.ACTIVE, now.minus(LAST_SEEN_WRITE_INTERVAL));
    }

    /** Revokes every active token session for a subject as one security transaction. */
    public int revokeAllForPrincipal(String tenantId, String principalId) {
        List<IamSession> active = sessions.findActiveForPrincipalForUpdate(
                tenantId, principalId, IamSession.Status.ACTIVE);
        active.forEach(IamSession::revoke);
        // Identity disable (user, SCIM, CIAM suspend) ends every invocation context the subject originated, in the
        // same transaction. Assignment removal does not call this and stays bounded by token expiry (Phase 1.12).
        if (invocationContexts != null) invocationContexts.revokeForSubject(tenantId, principalId, "identity disabled");
        // Phase 3.10: a departed accountable owner suspends the workloads they were accountable for.
        if (workloadLifecycle != null) workloadLifecycle.onPrincipalDisabled(tenantId, principalId);
        return active.size();
    }

    private com.openwolf.iam.authority.lifecycle.WorkloadLifecycleService workloadLifecycle;

    @org.springframework.beans.factory.annotation.Autowired(required = false)
    void setWorkloadLifecycle(@org.springframework.context.annotation.Lazy
                              com.openwolf.iam.authority.lifecycle.WorkloadLifecycleService workloadLifecycle) {
        this.workloadLifecycle = workloadLifecycle;
    }

    private com.openwolf.iam.invocation.InvocationContextService invocationContexts;

    @org.springframework.beans.factory.annotation.Autowired(required = false)
    void setInvocationContexts(@org.springframework.context.annotation.Lazy
                               com.openwolf.iam.invocation.InvocationContextService invocationContexts) {
        this.invocationContexts = invocationContexts;
    }

    private IamSession sessionForTenant(String tenantId, UUID id) {
        requireTenantAdmin(tenantId);
        return sessions.findByIdAndTenantId(id, tenantId).orElseThrow(() -> EntityNotFoundException.forId("Session", id));
    }

    private void requireTenantAdmin(String tenantId) {
        String callerTenant = executionTenant.require();
        if (tenantId.equals(callerTenant)) return;
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        boolean platformAdmin = authentication != null && authentication.getAuthorities().stream()
                .anyMatch(a -> "ROLE_platform_admin".equals(a.getAuthority()));
        if (!platformAdmin) throw EntityNotFoundException.forId("Session", tenantId);
    }

    private String currentSubject() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth == null || auth.getPrincipal() == null) throw new IllegalStateException("authenticated subject is required");
        if (auth.getPrincipal() instanceof Jwt jwt && jwt.getSubject() != null) return jwt.getSubject();
        return auth.getName();
    }

    private static void requireRevision(IamSession session, long expected) {
        if (session.getRevision() != expected) throw new ResourceConflictException("Session revision is stale");
    }

    private IamSessionResponse response(IamSession session) { return response(session, session.getRevision()); }
    private IamSessionResponse response(IamSession s, long revision) {
        return new IamSessionResponse(s.getId(), s.getTenantId(), s.getPrincipalId(), s.getApplicationId(), s.getClientId(),
                s.getIssuedAt(), s.getLastSeenAt(), s.getExpiresAt(), s.getStatus(), revision,
                s.isRecoveryMarked(), s.getRecoveryScope());
    }
}
