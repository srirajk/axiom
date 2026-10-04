package com.openwolf.iam.invocation;

import com.openwolf.iam.service.AuditService;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;
import java.util.UUID;

/** Tenant-administrator view and revocation of invocation contexts (Phase 2.9). No bearer token is ever returned. */
@RestController
@RequestMapping("/admin/tenants/{tenantId}/invocation-contexts")
@PreAuthorize("hasRole('platform_admin') or (hasRole('tenant_admin') and "
        + "#tenantId == authentication.token.claims['tenant_id'])")
public class InvocationContextController {
    private final InvocationContextService contexts;
    private final AuditService audit;

    public InvocationContextController(InvocationContextService contexts, AuditService audit) {
        this.contexts = contexts;
        this.audit = audit;
    }

    @GetMapping("/{contextId}")
    public ResponseEntity<Map<String, Object>> describe(@PathVariable String tenantId, @PathVariable UUID contextId) {
        return ResponseEntity.ok(contexts.describe(tenantId, contextId));
    }

    /** Revokes the context and every branch below it; idempotent (a revoked context stays revoked). */
    @PostMapping("/{contextId}/revoke")
    public ResponseEntity<Map<String, Object>> revoke(@PathVariable String tenantId, @PathVariable UUID contextId,
                                                      @RequestBody(required = false) Map<String, String> body) {
        String reason = body == null ? "administrative revocation" : body.getOrDefault("reason", "administrative revocation");
        int revoked = contexts.revoke(tenantId, contextId, reason, audit.currentActor());
        Map<String, Object> result = new java.util.LinkedHashMap<>(contexts.describe(tenantId, contextId));
        result.put("revoked_contexts", revoked);
        return ResponseEntity.ok(result);
    }
}
