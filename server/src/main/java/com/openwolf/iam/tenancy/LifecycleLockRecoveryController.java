package com.openwolf.iam.tenancy;

import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/** Protected two-person lifecycle recovery surface; no caller-supplied owner or evidence fields. */
@RestController
@RequestMapping("/admin/lifecycle-lock-recoveries")
public class LifecycleLockRecoveryController {

    private final LifecycleLockRecoveryService recovery;

    public LifecycleLockRecoveryController(LifecycleLockRecoveryService recovery) {
        this.recovery = recovery;
    }

    /** Operator creates a server-observed, immutable recovery request. */
    @PostMapping
    @PreAuthorize("hasRole('platform_admin')")
    public ResponseEntity<LifecycleLockRecoveryService.RecoveryResponse> request(Authentication auth) {
        return ResponseEntity.ok(recovery.request(tenant(auth), actor(auth)));
    }

    /** A distinct security approver approves the exact persisted observation and clears atomically. */
    @PostMapping("/{correlationId}/approve")
    @PreAuthorize("hasAnyRole('security_reviewer', 'policy_approver')")
    public ResponseEntity<LifecycleLockRecoveryService.RecoveryResponse> approve(
            @PathVariable String correlationId, Authentication auth) {
        return ResponseEntity.ok(recovery.approve(tenant(auth), correlationId, actor(auth)));
    }

    private static String actor(Authentication auth) {
        if (auth == null || auth.getName() == null || auth.getName().isBlank()) {
            throw new ProvisioningException("authenticated recovery identity is required");
        }
        return auth.getName();
    }

    private static String tenant(Authentication auth) {
        if (auth != null && auth.getPrincipal() instanceof Jwt jwt) {
            String tenant = jwt.getClaimAsString("tenant_id");
            if (tenant != null && !tenant.isBlank()) return tenant;
        }
        throw new ProvisioningException("authenticated recovery principal has no tenant_id claim");
    }
}
