package com.openwolf.iam.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.openwolf.iam.entity.AuditLog;
import com.openwolf.iam.auth.ExecutionTenant;
import com.openwolf.iam.repository.AuditLogRepository;
import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Service;

/**
 * Records immutable audit entries for every write operation in the IAM service.
 * <p>
 * CRITICAL: audit failures MUST NOT propagate to the caller — they are caught and logged
 * internally. An audit write error must never break the primary request.
 * </p>
 */
@Service
public class AuditService {

    private static final Logger log = LoggerFactory.getLogger(AuditService.class);

    private final AuditLogRepository auditLogRepository;
    private final ObjectMapper objectMapper;
    private final ExecutionTenant executionTenant;

    public AuditService(AuditLogRepository auditLogRepository, ObjectMapper objectMapper, ExecutionTenant executionTenant) {
        this.auditLogRepository = auditLogRepository;
        this.objectMapper = objectMapper;
        this.executionTenant = executionTenant;
    }

    /**
     * Writes an audit log entry. Never throws — all exceptions are swallowed and logged.
     *
     * @param tenantId     tenant this action belongs to
     * @param actorId      who performed the action (null = system)
     * @param action       what was done (e.g. "CREATE_USER", "ASSIGN_ROLE")
     * @param resourceType what kind of resource was affected (e.g. "user", "role")
     * @param resourceId   identifier of the affected resource
     * @param before       state before the change (null for creates)
     * @param after        state after the change (null for deletes)
     * @param req          HTTP request — used to capture source IP
     */
    public void log(String tenantId, String actorId, String action,
                    String resourceType, String resourceId,
                    Object before, Object after, HttpServletRequest req) {
        try {
            if (tenantId == null || tenantId.isBlank()) {
                throw new IllegalArgumentException("tenant-qualified audit logging requires a tenant id");
            }
            String beforeJson = toJson(before);
            String afterJson = toJson(after);
            String sourceIp = extractClientIp(req);
            String correlationId = req != null ? req.getHeader("X-Correlation-ID") : null;

            AuditLog entry = new AuditLog(
                    tenantId,
                    actorId,
                    "system",
                    action,
                    resourceType,
                    resourceId,
                    beforeJson,
                    afterJson,
                    sourceIp,
                    correlationId
            );
            auditLogRepository.save(entry);
        } catch (Exception ex) {
            // Never break the request — log and continue
            log.error("Failed to write audit log for action={} resource={}/{}: {}",
                    action, resourceType, resourceId, ex.getMessage(), ex);
        }
    }

    /**
     * Writes an auditable lifecycle fact whose persistence is part of the caller's transaction.
     * This is intentionally separate from best-effort request auditing: a one-time bootstrap must
     * never report success unless its durable audit fact exists.
     */
    public void logRequired(String tenantId, String actorId, String action,
                            String resourceType, String resourceId,
                            Object before, Object after, String correlationId) {
        AuditLog entry = new AuditLog(
                tenantId, actorId, "axiom-bootstrap", action, resourceType, resourceId,
                toJson(before), toJson(after), null, correlationId);
        auditLogRepository.save(entry);
    }

    /**
     * Records a non-mutating ACCESS audit event — e.g. a user entering a client
     * application on successful OIDC authentication ("who entered"). This is additive
     * audit <em>around</em> authentication: it records the fact of a successful login,
     * it never participates in or alters the authentication decision.
     * <p>
     * The {@code clientId} tags which application was entered (e.g. {@code axiom-admin}
     * vs the admin console) so chat-access is distinct in the audit log. Never throws —
     * an audit-write failure must never break login.
     *
     * @param actorId      the authenticated user id ("who")
     * @param clientId     the OIDC client the user authenticated into ("where")
     * @param action       the access event name (e.g. {@code chat_access})
     * @param resourceType the audited resource kind
     * @param resourceId   the audited resource identifier
     * @param sourceIp     best-effort source IP, may be null
     */
    public void logAccess(String actorId, String clientId, String action,
                          String resourceType, String resourceId, String sourceIp) {
        try {
            AuditLog entry = new AuditLog(
                    currentTenant(), actorId, clientId, action,
                    resourceType, resourceId, null, null, sourceIp, null);
            auditLogRepository.save(entry);
            log.info("Audit access event: actor={} action={} client={}", actorId, action, clientId);
        } catch (Exception ex) {
            // Never break the request — log and continue
            log.error("Failed to write access audit log for actor={} action={} client={}: {}",
                    actorId, action, clientId, ex.getMessage(), ex);
        }
    }

    /**
     * Resolves the current actor's user ID from the Spring Security context.
     * Returns "system" if no authenticated principal is present.
     */
    public String currentActor() {
        try {
            var authentication = SecurityContextHolder.getContext().getAuthentication();
            if (authentication == null || !authentication.isAuthenticated()) {
                return "system";
            }
            Object principal = authentication.getPrincipal();
            if (principal instanceof Jwt jwt) {
                String sub = jwt.getSubject();
                return sub != null ? sub : "system";
            }
            return authentication.getName() != null ? authentication.getName() : "system";
        } catch (Exception ex) {
            log.warn("Could not resolve current actor from security context: {}", ex.getMessage());
            return "system";
        }
    }

    /**
     * Resolves the current execution tenant from the verified JWT ({@code tenant_id} claim) in the
     * Spring Security context (Axiom A6). This is the tenant the caller is authenticated into — the
     * audit read/export scopes to it, so an examiner never sees another tenant's records. A missing
     * claim fails closed; bootstrap uses {@link #logRequired} with its explicit service tenant.
     */
    public String currentTenant() {
        return executionTenant.require();
    }

    private String toJson(Object value) {
        if (value == null) return null;
        try {
            if (value instanceof String s) return s;
            return objectMapper.writeValueAsString(value);
        } catch (JsonProcessingException ex) {
            log.warn("Failed to serialise audit state to JSON: {}", ex.getMessage());
            return "{\"error\":\"serialisation_failed\"}";
        }
    }

    private String extractClientIp(HttpServletRequest req) {
        if (req == null) return null;
        String forwarded = req.getHeader("X-Forwarded-For");
        if (forwarded != null && !forwarded.isBlank()) {
            return forwarded.split(",")[0].trim();
        }
        return req.getRemoteAddr();
    }
}
