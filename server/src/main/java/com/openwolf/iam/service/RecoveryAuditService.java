package com.openwolf.iam.service;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

/** Commits a recovery rejection audit independently before the uniform failure is returned. */
@Service
public class RecoveryAuditService {
    private final AuditService audit;

    public RecoveryAuditService(AuditService audit) { this.audit = audit; }

    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void rejected(String tenantId, String reason) {
        rejected(tenantId, "REJECT_IDENTITY_RECOVERY_SESSION", tenantId, reason);
    }

    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void rejected(String tenantId, String action, String resourceId, String reason) {
        audit.logRequired(tenantId, audit.currentActor(), action, "identity_recovery", resourceId,
                null, java.util.Map.of("status", "rejected", "reason", reason), null);
    }
}
