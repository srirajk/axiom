package com.openwolf.iam.service;

import com.openwolf.iam.entity.IdentityControlRequest;
import com.openwolf.iam.exception.EntityNotFoundException;
import com.openwolf.iam.repository.IdentityControlRequestRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;

/** Commits expiry and its required audit independently of a rejected outer transition. */
@Service
public class IdentityControlRequestExpiryService {
    private final IdentityControlRequestRepository requests;
    private final AuditService audit;

    public IdentityControlRequestExpiryService(IdentityControlRequestRepository requests, AuditService audit) {
        this.requests = requests; this.audit = audit;
    }

    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public boolean expireIfDue(String tenantId, UUID id, Instant now) {
        IdentityControlRequest request = requests.findForUpdateByIdAndTenantId(id, tenantId)
                .orElseThrow(() -> EntityNotFoundException.forId("Identity control request", id));
        if (request.getStatus() == IdentityControlRequest.Status.EXPIRED) return true;
        if ((request.getStatus() != IdentityControlRequest.Status.PENDING
                && request.getStatus() != IdentityControlRequest.Status.APPROVED)
                || !request.getExpiresAt().isBefore(now)) return false;

        request.expire();
        requests.saveAndFlush(request);
        Map<String, Object> after = new LinkedHashMap<>();
        after.put("request_id", request.getId().toString());
        after.put("status", request.getStatus().name());
        after.put("revision", request.getRevision() + 1);
        audit.logRequired(tenantId, audit.currentActor(), "EXPIRE_IDENTITY_CONTROL_REQUEST",
                "identity_control_request", request.getId().toString(), null, after, null);
        return true;
    }
}
