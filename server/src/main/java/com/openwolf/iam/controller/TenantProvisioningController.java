package com.openwolf.iam.controller;

import com.openwolf.iam.tenancy.ActiveTenantDirectory;
import com.openwolf.iam.tenancy.ProvisioningRequest;
import com.openwolf.iam.tenancy.ProvisioningResult;
import com.openwolf.iam.tenancy.TenantProvisioningService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Admin control-plane for tenant provisioning / deprovisioning (Axiom B4). Platform-admin only (and
 * additionally behind the {@code /admin/**} gate in {@code SecurityConfig}). Writes never touch the
 * serving request path; a tenant only becomes visible after the atomic activation CAS.
 *
 * <p>Provisioning a real customer tenant against the live stack is intentionally NOT done here — it
 * is held for the operator. These endpoints are the mechanism.
 */
@RestController
@RequestMapping("/admin/tenants")
@PreAuthorize("hasRole('platform_admin')")
public class TenantProvisioningController {

    private final TenantProvisioningService provisioningService;
    private final ActiveTenantDirectory directory;

    public TenantProvisioningController(TenantProvisioningService provisioningService,
                                        ActiveTenantDirectory directory) {
        this.provisioningService = provisioningService;
        this.directory = directory;
    }

    public record ProvisionBody(String tenantId, String name, String slug) {}

    /** {@code POST /admin/tenants} — provision (idempotent on the {@code Idempotency-Key} header). */
    @PostMapping
    public ResponseEntity<ProvisioningResult> provision(
            @RequestBody ProvisionBody body,
            @RequestHeader("Idempotency-Key") String idempotencyKey,
            Authentication authentication) {
        ProvisioningResult result = provisioningService.provision(
                new ProvisioningRequest(body.tenantId(), body.name(), body.slug()),
                idempotencyKey, actorOf(authentication));
        return ResponseEntity.status(result.isActive() ? HttpStatus.CREATED : HttpStatus.ACCEPTED).body(result);
    }

    /** {@code DELETE /admin/tenants/{id}} — deprovision (revokes visibility, retains audit). */
    @DeleteMapping("/{tenantId}")
    public ResponseEntity<Void> deprovision(
            @PathVariable String tenantId,
            @RequestHeader("Idempotency-Key") String idempotencyKey,
            Authentication authentication) {
        provisioningService.deprovision(tenantId, idempotencyKey, actorOf(authentication));
        return ResponseEntity.noContent().build();
    }

    /** {@code GET /admin/tenants/directory} — the active-tenant directory snapshot. */
    @GetMapping("/directory")
    public ResponseEntity<ActiveTenantDirectory.Snapshot> directory() {
        return ResponseEntity.ok(directory.snapshot());
    }

    /** One tenant's atomic three-artifact activation status, derived from the active directory. */
    public record TenantStatus(String tenantId, boolean active, String policyVersion, long directoryVersion) {}

    /** The list envelope — the current directory version plus every active tenant's status. */
    public record TenantList(long directoryVersion, java.util.List<TenantStatus> tenants) {}

    /**
     * {@code GET /admin/tenants} — list every active tenant with its status. "Active" means the
     * activation compare-and-set (the last step of a provision, after all three artifacts verified)
     * committed; a half-provisioned or deprovisioned tenant is simply absent.
     */
    @GetMapping
    public ResponseEntity<TenantList> list() {
        ActiveTenantDirectory.Snapshot snapshot = directory.snapshot();
        java.util.List<TenantStatus> tenants = snapshot.tenantPolicyVersions().entrySet().stream()
                .map(e -> new TenantStatus(e.getKey(), true, e.getValue(), snapshot.version()))
                .sorted(java.util.Comparator.comparing(TenantStatus::tenantId))
                .toList();
        return ResponseEntity.ok(new TenantList(snapshot.version(), tenants));
    }

    /**
     * {@code GET /admin/tenants/{tenantId}} — one tenant's status. Present ⇒ {@code active=true} with
     * its live policy version; absent ⇒ {@code active=false} (fails closed, never a guess).
     */
    @GetMapping("/{tenantId}")
    public ResponseEntity<TenantStatus> status(@PathVariable String tenantId) {
        ActiveTenantDirectory.Snapshot snapshot = directory.snapshot();
        String policyVersion = snapshot.tenantPolicyVersions().get(tenantId);
        return ResponseEntity.ok(new TenantStatus(
                tenantId, policyVersion != null, policyVersion, snapshot.version()));
    }

    private static String actorOf(Authentication authentication) {
        return authentication != null && authentication.getName() != null
                ? authentication.getName() : "system";
    }
}
