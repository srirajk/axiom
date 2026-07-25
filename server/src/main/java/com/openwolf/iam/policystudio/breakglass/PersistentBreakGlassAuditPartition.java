package com.openwolf.iam.policystudio.breakglass;

import com.openwolf.iam.entity.AuditLog;
import com.openwolf.iam.repository.AuditLogRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import org.springframework.dao.DataIntegrityViolationException;

import java.util.List;

/**
 * Real break-glass audit sink (Axiom Story C6.3) over the {@code audit_log} table — the same A6
 * partition {@link com.openwolf.iam.tenancy.PersistentAuditPartitionAdapter} materialises for tenant
 * provisioning. A grant issuance and each use append a {@code tenant_id}-scoped row; there is
 * deliberately NO delete, so the emergency-access evidence is retained.
 */
@Component
public class PersistentBreakGlassAuditPartition implements BreakGlassAuditPartition {

    private static final Logger log = LoggerFactory.getLogger(PersistentBreakGlassAuditPartition.class);

    private static final String RESOURCE_TYPE = "break_glass";
    private static final String ACTION_GRANTED = "break_glass.granted";
    private static final String ACTION_USED = "break_glass.used";

    private final AuditLogRepository auditLogRepository;

    public PersistentBreakGlassAuditPartition(AuditLogRepository auditLogRepository) {
        this.auditLogRepository = auditLogRepository;
    }

    @Override
    public void recordGranted(BreakGlassGrant grant, String approverId, String correlationId) {
        appendIdempotently(grant.tenantId(), ACTION_GRANTED, grant.scope().value(), correlationId, new AuditLog(
                grant.tenantId(), grant.requestedBy(), "system",
                ACTION_GRANTED, RESOURCE_TYPE, grant.scope().value(),
                null, grantedState(grant, approverId), null, correlationId));
        log.info("Break-glass GRANTED tenant='{}' scope='{}' action='{}' role='{}' expiresAt={} "
                        + "requestedBy='{}' approvedBy='{}'",
                grant.tenantId(), grant.scope().value(), grant.action(), grant.role(),
                grant.expiresAt(), grant.requestedBy(), approverId);
    }

    @Override
    public void recordUsed(BreakGlassGrant grant, String principalId, String action, String correlationId) {
        recordUsed(null, grant, principalId, action, correlationId);
    }

    @Override
    public void recordUsed(String grantId, BreakGlassGrant grant, String principalId,
                           String action, String correlationId) {
        String auditResourceId = grantId == null || grantId.isBlank() ? grant.scope().value() : grantId;
        appendIdempotently(grant.tenantId(), ACTION_USED, auditResourceId, correlationId, new AuditLog(
                grant.tenantId(), principalId, "system",
                ACTION_USED, RESOURCE_TYPE, auditResourceId,
                null, usedState(grantId, grant, principalId, action), null, correlationId));
        log.info("Break-glass USED tenant='{}' scope='{}' action='{}' by principal='{}'",
                grant.tenantId(), grant.scope().value(), action, principalId);
    }

    @Override
    public List<AuditLog> partition(String tenantId) {
        return auditLogRepository.findByTenantIdOrderByOccurredAtDesc(tenantId);
    }

    private void appendIdempotently(String tenantId, String action, String resourceId,
                                    String correlationId, AuditLog entry) {
        if (correlationId != null && auditLogRepository
                .existsByTenantIdAndActionAndResourceTypeAndResourceIdAndCorrelationId(
                        tenantId, action, RESOURCE_TYPE, resourceId, correlationId)) {
            return;
        }
        try {
            auditLogRepository.saveAndFlush(entry);
        } catch (DataIntegrityViolationException duplicate) {
            if (correlationId == null || !auditLogRepository
                    .existsByTenantIdAndActionAndResourceTypeAndResourceIdAndCorrelationId(
                            tenantId, action, RESOURCE_TYPE, resourceId, correlationId)) {
                throw duplicate;
            }
        }
    }

    private static String grantedState(BreakGlassGrant grant, String approverId) {
        return "{\"event\":\"granted\""
                + ",\"scope\":\"" + grant.scope().value() + "\""
                + ",\"resource\":\"" + grant.resourceKind() + "\""
                + ",\"action\":\"" + grant.action() + "\""
                + ",\"role\":\"" + grant.role() + "\""
                + ",\"issuedAt\":\"" + grant.issuedAt() + "\""
                + ",\"expiresAt\":\"" + grant.expiresAt() + "\""
                + ",\"requestedBy\":\"" + grant.requestedBy() + "\""
                + ",\"approvedBy\":\"" + approverId + "\""
                + ",\"justification\":\"" + escape(grant.justification()) + "\"}";
    }

    private static String usedState(String grantId, BreakGlassGrant grant, String principalId, String action) {
        return "{\"event\":\"used\""
                + ",\"grantId\":\"" + escape(grantId) + "\""
                + ",\"scope\":\"" + grant.scope().value() + "\""
                + ",\"action\":\"" + action + "\""
                + ",\"principal\":\"" + principalId + "\""
                + ",\"expiresAt\":\"" + grant.expiresAt() + "\"}";
    }

    private static String escape(String s) {
        return s == null ? "" : s.replace("\\", "\\\\").replace("\"", "\\\"");
    }
}
