package com.openwolf.iam.service;

import com.openwolf.iam.auth.ExecutionTenant;
import com.openwolf.iam.dto.IamSessionResponse;
import com.openwolf.iam.dto.RevokeIamSessionRequest;
import com.openwolf.iam.entity.IamSession;
import com.openwolf.iam.exception.EntityNotFoundException;
import com.openwolf.iam.exception.ResourceConflictException;
import com.openwolf.iam.repository.IamSessionRepository;
import com.openwolf.iam.repository.RecoveryOperatorRepository;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Instant;
import java.util.List;
import java.util.UUID;

@Service
@Transactional
public class IamSessionService {
    private final IamSessionRepository sessions;
    private final ExecutionTenant executionTenant;
    private final AuditService audit;
    private final RecoveryOperatorRepository recoveryOperators;
    private final Clock clock;

    @Autowired
    public IamSessionService(IamSessionRepository sessions, ExecutionTenant executionTenant, AuditService audit,
                             RecoveryOperatorRepository recoveryOperators) {
        this(sessions, executionTenant, audit, Clock.systemUTC(), recoveryOperators);
    }

    IamSessionService(IamSessionRepository sessions, ExecutionTenant executionTenant, AuditService audit, Clock clock) {
        this(sessions, executionTenant, audit, clock, null);
    }

    IamSessionService(IamSessionRepository sessions, ExecutionTenant executionTenant, AuditService audit, Clock clock,
                      RecoveryOperatorRepository recoveryOperators) {
        this.sessions = sessions; this.executionTenant = executionTenant; this.audit = audit;
        this.clock = clock; this.recoveryOperators = recoveryOperators;
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
            sessions.touch(id, tenantId, now, IamSession.Status.ACTIVE);
            return id;
        }
        sessions.save(new IamSession(id, tenantId, principalId, applicationId, clientId, now, expiresAt));
        return id;
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
        IamSessionResponse after = response(session, session.getRevision() + 1);
        audit.logRequired(tenantId, audit.currentActor(), "REVOKE_SESSION", "session", id.toString(), before, after,
                httpRequest == null ? null : httpRequest.getHeader("X-Correlation-ID"));
        return after;
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
    public void touch(UUID id, String tenantId, Instant now) { sessions.touch(id, tenantId, now, IamSession.Status.ACTIVE); }

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
