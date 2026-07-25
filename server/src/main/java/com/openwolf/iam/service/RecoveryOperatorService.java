package com.openwolf.iam.service;

import com.openwolf.iam.auth.ExecutionTenant;
import com.openwolf.iam.dto.EnrollRecoveryOperatorRequest;
import com.openwolf.iam.dto.RecoveryOperatorResponse;
import com.openwolf.iam.dto.RecoveryOperatorTransitionRequest;
import com.openwolf.iam.dto.IamSessionResponse;
import com.openwolf.iam.entity.IamSession;
import com.openwolf.iam.entity.Principal;
import com.openwolf.iam.entity.RecoveryOperator;
import com.openwolf.iam.exception.EntityNotFoundException;
import com.openwolf.iam.exception.ResourceConflictException;
import com.openwolf.iam.repository.PrincipalRepository;
import com.openwolf.iam.repository.RecoveryOperatorRepository;
import com.openwolf.iam.repository.IamSessionRepository;
import com.openwolf.iam.service.RecoveryAuditService;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.security.SecureRandom;
import java.time.Clock;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.UUID;

@Service
@Transactional
public class RecoveryOperatorService {
    private final RecoveryOperatorRepository operators;
    private final PrincipalRepository principals;
    private final ExecutionTenant executionTenant;
    private final PasswordEncoder passwords;
    private final AuditService audit;
    private final IamSessionRepository sessions;
    private final RecoveryAuditService recoveryAudit;
    private final Clock clock;
    private final SecureRandom random = new SecureRandom();

    @Autowired
    public RecoveryOperatorService(RecoveryOperatorRepository operators, PrincipalRepository principals,
                                   ExecutionTenant executionTenant, PasswordEncoder passwords, AuditService audit,
                                   IamSessionRepository sessions, RecoveryAuditService recoveryAudit) {
        this(operators, principals, executionTenant, passwords, audit, sessions, recoveryAudit, Clock.systemUTC());
    }

    RecoveryOperatorService(RecoveryOperatorRepository operators, PrincipalRepository principals,
                            ExecutionTenant executionTenant, PasswordEncoder passwords, AuditService audit, Clock clock) {
        this(operators, principals, executionTenant, passwords, audit, null, null, clock);
    }

    RecoveryOperatorService(RecoveryOperatorRepository operators, PrincipalRepository principals,
                            ExecutionTenant executionTenant, PasswordEncoder passwords, AuditService audit,
                            IamSessionRepository sessions, RecoveryAuditService recoveryAudit, Clock clock) {
        this.operators = operators; this.principals = principals; this.executionTenant = executionTenant;
        this.passwords = passwords; this.audit = audit; this.sessions = sessions;
        this.recoveryAudit = recoveryAudit; this.clock = clock;
    }

    public List<RecoveryOperatorResponse> list(String tenantId) {
        requireTenantAdmin(tenantId);
        return operators.findByTenantIdOrderByCreatedAt(tenantId).stream().map(operator -> response(operator, null)).toList();
    }

    @Transactional(readOnly = true)
    public List<RecoveryOperatorResponse> selfList() {
        String tenantId = executionTenant.require();
        String principalId = requireNormalSelf(tenantId);
        return operators.findByTenantIdAndPrincipalId(tenantId, principalId)
                .map(operator -> response(operator, null)).stream().toList();
    }

    public RecoveryOperatorResponse enroll(String tenantId, EnrollRecoveryOperatorRequest request,
                                           HttpServletRequest httpRequest) {
        requireTenantAdmin(tenantId);
        String initiator = audit.currentActor();
        if (request.principalId().equals(initiator)) reject(tenantId, "REJECT_IDENTITY_RECOVERY_ENROLLMENT", request.principalId(), "initiator cannot enroll self");
        Principal principal = principals.findByIdAndTenantId(request.principalId(), tenantId)
                .filter(Principal::isActive)
                .orElseThrow(() -> EntityNotFoundException.forId("Principal", request.principalId()));
        RecoveryOperator existing = operators.findByTenantIdAndPrincipalId(tenantId, principal.getId()).orElse(null);
        if (existing != null) {
            if (existing.getStatus() != RecoveryOperator.Status.DISABLED) throw new ResourceConflictException("recovery operator already enrolled");
            existing.beginActivation(initiator, clock.instant());
            operators.saveAndFlush(existing);
            audit.logRequired(tenantId, initiator, "ENROLL_IDENTITY_RECOVERY_OPERATOR",
                    "identity_recovery_operator", existing.getId().toString(), null, response(existing, null), correlation(httpRequest));
            return response(existing, null);
        }
        RecoveryOperator operator = operators.saveAndFlush(RecoveryOperator.pending(tenantId, principal.getId(), initiator, clock.instant()));
        audit.logRequired(tenantId, initiator, "ENROLL_IDENTITY_RECOVERY_OPERATOR",
                "identity_recovery_operator", operator.getId().toString(), null, response(operator, null), correlation(httpRequest));
        return response(operator, null);
    }

    public RecoveryOperatorResponse rotate(String tenantId, UUID id, RecoveryOperatorTransitionRequest request,
                                           HttpServletRequest httpRequest) {
        requireTenantAdmin(tenantId);
        RecoveryOperator operator = operators.findByIdAndTenantIdForUpdate(id, tenantId)
                .orElseThrow(() -> EntityNotFoundException.forId("Recovery operator", id));
        requireRevision(operator, request.expectedRevision());
        String initiator = audit.currentActor();
        if (operator.getPrincipalId().equals(initiator)) reject(tenantId, "REJECT_IDENTITY_RECOVERY_ROTATION", id.toString(), "initiator cannot rotate self");
        operator.beginRotation(initiator, clock.instant());
        operators.saveAndFlush(operator);
        revokeSessions(operator);
        audit.logRequired(tenantId, initiator, "ROTATE_IDENTITY_RECOVERY_CREDENTIAL",
                "identity_recovery_operator", id.toString(), null, response(operator, null), correlation(httpRequest));
        return response(operator, null);
    }

    public RecoveryOperatorResponse disable(String tenantId, UUID id, RecoveryOperatorTransitionRequest request,
                                            HttpServletRequest httpRequest) {
        requireTenantAdmin(tenantId);
        RecoveryOperator operator = operators.findByIdAndTenantIdForUpdate(id, tenantId)
                .orElseThrow(() -> EntityNotFoundException.forId("Recovery operator", id));
        requireRevision(operator, request.expectedRevision());
        if (operator.getStatus() != RecoveryOperator.Status.DISABLED) operator.disable(clock.instant());
        operators.saveAndFlush(operator);
        revokeSessions(operator);
        audit.logRequired(tenantId, audit.currentActor(), "DISABLE_IDENTITY_RECOVERY_OPERATOR",
                "identity_recovery_operator", id.toString(), null, response(operator, null), correlation(httpRequest));
        return response(operator, null);
    }

    public RecoveryOperatorResponse activateSelf(UUID id, RecoveryOperatorTransitionRequest request,
                                                 HttpServletRequest httpRequest) {
        return completeSelf(id, request, RecoveryOperator.Status.PENDING_ACTIVATION,
                "ACTIVATE_IDENTITY_RECOVERY_OPERATOR", httpRequest);
    }

    public RecoveryOperatorResponse completeRotationSelf(UUID id, RecoveryOperatorTransitionRequest request,
                                                         HttpServletRequest httpRequest) {
        return completeSelf(id, request, RecoveryOperator.Status.PENDING_ROTATION,
                "ACTIVATE_IDENTITY_RECOVERY_CREDENTIAL", httpRequest);
    }

    private RecoveryOperatorResponse completeSelf(UUID id, RecoveryOperatorTransitionRequest request,
                                                  RecoveryOperator.Status expectedStatus, String action,
                                                  HttpServletRequest httpRequest) {
        String tenantId = executionTenant.require();
        String actor = requireNormalSelf(tenantId);
        RecoveryOperator operator = operators.findByIdAndTenantIdForUpdate(id, tenantId).orElse(null);
        if (operator == null || operator.getStatus() != expectedStatus || operator.getRevision() != request.expectedRevision()
                || !actor.equals(operator.getPrincipalId()) || actor.equals(operator.getInitiatorPrincipalId())) {
            return reject(tenantId, "REJECT_IDENTITY_RECOVERY_ACTIVATION", id.toString(), "activation failed");
        }
        Principal principal = principals.findByIdAndTenantId(actor, tenantId).filter(Principal::isActive).orElse(null);
        if (principal == null) return reject(tenantId, "REJECT_IDENTITY_RECOVERY_ACTIVATION", id.toString(), "activation failed");
        String credential = generateCredential();
        operator.activate(passwords.encode(credential), actor, clock.instant());
        operators.saveAndFlush(operator);
        audit.logRequired(tenantId, actor, action, "identity_recovery_operator", id.toString(), null,
                response(operator, null), correlation(httpRequest));
        return response(operator, credential);
    }

    private String requireNormalSelf(String tenantId) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null || !(authentication.getPrincipal() instanceof Jwt jwt)) {
            throw new ResourceConflictException("recovery operator activation failed");
        }
        if (!tenantId.equals(jwt.getClaimAsString("tenant_id")) || Boolean.TRUE.equals(jwt.getClaims().get("recovery"))
                || Boolean.TRUE.equals(jwt.getClaims().get("impersonation")) || jwt.getSubject() == null
                || jwt.getSubject().isBlank()) {
            throw new ResourceConflictException("recovery operator activation failed");
        }
        return jwt.getSubject();
    }

    private RecoveryOperatorResponse reject(String tenantId, String action, String resourceId, String reason) {
        if (recoveryAudit != null) recoveryAudit.rejected(tenantId, action, resourceId, reason);
        throw new ResourceConflictException("recovery operator activation failed");
    }

    private void requireTenantAdmin(String tenantId) {
        if (tenantId.equals(executionTenant.require()) || isPlatformAdmin()) return;
        throw EntityNotFoundException.forId("Recovery operator", tenantId);
    }

    private boolean isPlatformAdmin() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        return authentication != null && authentication.getAuthorities().stream()
                .anyMatch(authority -> "ROLE_platform_admin".equals(authority.getAuthority()));
    }

    private String generateCredential() {
        byte[] bytes = new byte[32]; random.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    private static void requireRevision(RecoveryOperator operator, long expected) {
        if (operator.getRevision() != expected) throw new ResourceConflictException("recovery operator revision is stale");
    }

    private void revokeSessions(RecoveryOperator operator) {
        if (sessions == null) return;
        for (IamSession session : sessions.findActiveRecoverySessionsForOperatorForUpdate(operator.getTenantId(),
                operator.getId(), IamSession.Status.ACTIVE)) {
            IamSessionResponse before = sessionResponse(session);
            session.revoke();
            sessions.saveAndFlush(session);
            IamSessionResponse after = sessionResponse(session);
            audit.logRequired(operator.getTenantId(), audit.currentActor(), "REVOKE_IDENTITY_RECOVERY_SESSION",
                    "session", session.getId().toString(), before, after, null);
        }
    }

    private static IamSessionResponse sessionResponse(IamSession session) {
        return new IamSessionResponse(session.getId(), session.getTenantId(), session.getPrincipalId(),
                session.getApplicationId(), session.getClientId(), session.getIssuedAt(), session.getLastSeenAt(),
                session.getExpiresAt(), session.getStatus(), session.getRevision(), session.isRecoveryMarked(),
                session.getRecoveryScope());
    }

    private static RecoveryOperatorResponse response(RecoveryOperator operator, String credential) {
        return new RecoveryOperatorResponse(operator.getId(), operator.getTenantId(), operator.getPrincipalId(),
                operator.getStatus(), operator.getRevision(), operator.getCreatedAt(), operator.getUpdatedAt(),
                operator.getInitiatorPrincipalId(), operator.getActivationActorId(), operator.getActivationAt(), credential);
    }

    private static String correlation(HttpServletRequest request) { return request == null ? null : request.getHeader("X-Correlation-ID"); }
}
