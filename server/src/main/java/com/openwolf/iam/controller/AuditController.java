package com.openwolf.iam.controller;

import com.openwolf.iam.dto.AuditLogResponse;
import com.openwolf.iam.dto.PageResponse;
import com.openwolf.iam.entity.AuditLog;
import com.openwolf.iam.repository.AuditLogRepository;
import com.openwolf.iam.service.AuditService;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

/**
 * Paginated access to the audit log. All write operations in the IAM service
 * emit an entry — this endpoint is the read side.
 *
 * <p>Axiom A6: the read/export is scoped to the caller's <em>verified execution tenant</em>
 * ({@code tenant_id} claim resolved by {@link AuditService#currentTenant()}), never a hard-coded
 * {@code "default"}. An examiner sees only their own tenant's records — the repository query already
 * filters by the tenant partition key, so cross-tenant records can never appear.
 */
@RestController
@RequestMapping("/admin/audit")
public class AuditController {

    private final AuditLogRepository auditLogRepository;
    private final AuditService auditService;

    public AuditController(AuditLogRepository auditLogRepository, AuditService auditService) {
        this.auditLogRepository = auditLogRepository;
        this.auditService = auditService;
    }

    /**
     * {@code GET /admin/audit} — paginated audit log for the caller's tenant, newest first.
     */
    @GetMapping
    public ResponseEntity<PageResponse<AuditLogResponse>> getAuditLog(
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "50") int size) {
        String tenantId = auditService.currentTenant();
        Page<AuditLog> auditPage = auditLogRepository
                .findByTenantIdOrderByOccurredAtDesc(tenantId, PageRequest.of(page, size));
        Page<AuditLogResponse> responsePage = auditPage.map(this::toResponse);
        return ResponseEntity.ok(PageResponse.of(responsePage));
    }

    /**
     * {@code GET /admin/audit/export} — full export (no pagination) for the caller's tenant.
     */
    @GetMapping("/export")
    public ResponseEntity<List<AuditLogResponse>> exportAuditLog() {
        String tenantId = auditService.currentTenant();
        List<AuditLogResponse> all = auditLogRepository
                .findByTenantIdOrderByOccurredAtDesc(tenantId)
                .stream()
                .map(this::toResponse)
                .toList();
        return ResponseEntity.ok(all);
    }

    private AuditLogResponse toResponse(AuditLog log) {
        return new AuditLogResponse(
                log.getId(),
                log.getTenantId(),
                log.getActorId(),
                log.getClientId(),
                log.getAction(),
                log.getResourceType(),
                log.getResourceId(),
                log.getBeforeState(),  // raw JSON string
                log.getAfterState(),   // raw JSON string
                log.getSourceIp(),
                log.getOccurredAt()
        );
    }
}
