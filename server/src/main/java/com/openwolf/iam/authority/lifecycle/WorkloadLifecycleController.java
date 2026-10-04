package com.openwolf.iam.authority.lifecycle;

import com.openwolf.iam.service.AuditService;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.UUID;

/** Tenant-administrator lifecycle of Agent workload identities (Phase 3.10/3.15). */
@RestController
@RequestMapping("/admin/tenants/{tenantId}/ciam/agent-workloads")
@PreAuthorize("hasRole('platform_admin') or (hasRole('tenant_admin') and "
        + "#tenantId == authentication.token.claims['tenant_id'])")
public class WorkloadLifecycleController {
    public record OwnershipRequest(@NotNull UUID teamId, @NotBlank @Size(max = 255) String accountablePrincipalId) {}

    public record ReasonRequest(@Size(max = 200) String reason) {}

    public record ReviewRequest(@NotNull WorkloadLifecycleService.ReviewDecision decision, @Size(max = 500) String notes) {}

    private final WorkloadLifecycleService lifecycle;
    private final AuditService audit;

    public WorkloadLifecycleController(WorkloadLifecycleService lifecycle, AuditService audit) {
        this.lifecycle = lifecycle;
        this.audit = audit;
    }

    @GetMapping("/lifecycle")
    public ResponseEntity<List<WorkloadLifecycleService.WorkloadView>> list(@PathVariable String tenantId) {
        return ResponseEntity.ok(lifecycle.list(tenantId));
    }

    @PostMapping("/{workloadId}/ownership")
    public ResponseEntity<WorkloadLifecycleService.WorkloadView> assign(@PathVariable String tenantId,
                                                                        @PathVariable UUID workloadId,
                                                                        @Valid @RequestBody OwnershipRequest request) {
        return ResponseEntity.ok(lifecycle.assignOwnership(tenantId, workloadId, request.teamId(),
                request.accountablePrincipalId(), audit.currentActor()));
    }

    @PostMapping("/{workloadId}/suspend")
    public ResponseEntity<WorkloadLifecycleService.WorkloadView> suspend(@PathVariable String tenantId,
                                                                         @PathVariable UUID workloadId,
                                                                         @Valid @RequestBody(required = false) ReasonRequest r) {
        return ResponseEntity.ok(lifecycle.suspend(tenantId, workloadId, r == null ? null : r.reason(), audit.currentActor()));
    }

    @PostMapping("/{workloadId}/reactivate")
    public ResponseEntity<WorkloadLifecycleService.WorkloadView> reactivate(@PathVariable String tenantId,
                                                                            @PathVariable UUID workloadId) {
        return ResponseEntity.ok(lifecycle.reactivate(tenantId, workloadId, audit.currentActor()));
    }

    @PostMapping("/{workloadId}/retire")
    public ResponseEntity<WorkloadLifecycleService.WorkloadView> retire(@PathVariable String tenantId,
                                                                        @PathVariable UUID workloadId,
                                                                        @Valid @RequestBody(required = false) ReasonRequest r) {
        return ResponseEntity.ok(lifecycle.retire(tenantId, workloadId, r == null ? null : r.reason(), audit.currentActor()));
    }

    @PostMapping("/{workloadId}/access-reviews")
    public ResponseEntity<WorkloadLifecycleService.WorkloadView> review(@PathVariable String tenantId,
                                                                        @PathVariable UUID workloadId,
                                                                        @Valid @RequestBody ReviewRequest r) {
        return ResponseEntity.ok(lifecycle.review(tenantId, workloadId, r.decision(), r.notes(), audit.currentActor()));
    }
}
