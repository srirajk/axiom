package com.openwolf.iam.authority.federation;

import com.openwolf.iam.service.AuditService;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
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

/** Tenant-administrator bindings of external workload identities to Agent workloads (Phase 3.12). */
@RestController
@RequestMapping("/admin/tenants/{tenantId}/ciam/agent-workloads/{workloadId}/federation-bindings")
@PreAuthorize("hasRole('platform_admin') or (hasRole('tenant_admin') and "
        + "#tenantId == authentication.token.claims['tenant_id'])")
public class WorkloadFederationController {
    public record BindRequest(@NotBlank @Size(max = 64) String providerProfile, @NotBlank @Size(max = 512) String issuer,
                              @NotBlank @Size(max = 512) String subject) {}

    private final WorkloadFederationService federation;
    private final AuditService audit;

    public WorkloadFederationController(WorkloadFederationService federation, AuditService audit) {
        this.federation = federation;
        this.audit = audit;
    }

    @PostMapping
    public ResponseEntity<WorkloadFederationService.BindingView> bind(@PathVariable String tenantId,
                                                                      @PathVariable UUID workloadId,
                                                                      @Valid @RequestBody BindRequest r) {
        return ResponseEntity.status(201).body(federation.bind(tenantId, workloadId, r.providerProfile(), r.issuer(),
                r.subject(), audit.currentActor()));
    }

    @GetMapping
    public ResponseEntity<List<WorkloadFederationService.BindingView>> list(@PathVariable String tenantId,
                                                                            @PathVariable UUID workloadId) {
        return ResponseEntity.ok(federation.list(tenantId, workloadId));
    }

    @PostMapping("/{bindingId}/revoke")
    public ResponseEntity<WorkloadFederationService.BindingView> revoke(@PathVariable String tenantId,
                                                                        @PathVariable UUID workloadId,
                                                                        @PathVariable UUID bindingId) {
        return ResponseEntity.ok(federation.revoke(tenantId, workloadId, bindingId, audit.currentActor()));
    }
}
