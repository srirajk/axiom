package com.openwolf.iam.authority.consent;

import com.openwolf.iam.service.AuditService;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.Positive;
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
import java.util.Set;
import java.util.UUID;

/** Tenant-administrator registry of consent purposes per Agent workload (Phase 3.2). */
@RestController
@RequestMapping("/admin/tenants/{tenantId}/ciam/agent-workloads/{workloadId}/purposes")
@PreAuthorize("hasRole('platform_admin') or (hasRole('tenant_admin') and "
        + "#tenantId == authentication.token.claims['tenant_id'])")
public class ConsentPurposeController {
    public record RegisterPurposeRequest(@NotBlank @Size(max = 64) String purposeCode,
                                         @NotBlank @Size(max = 500) String description,
                                         @NotEmpty Set<@NotBlank @Size(max = 120) String> scopes,
                                         @Positive long maxValiditySeconds) {}

    private final ConsentPurposeService purposes;
    private final AuditService audit;

    public ConsentPurposeController(ConsentPurposeService purposes, AuditService audit) {
        this.purposes = purposes;
        this.audit = audit;
    }

    @PostMapping
    public ResponseEntity<ConsentPurposeService.PurposeView> register(@PathVariable String tenantId,
                                                                      @PathVariable UUID workloadId,
                                                                      @Valid @RequestBody RegisterPurposeRequest request) {
        return ResponseEntity.status(201).body(purposes.register(tenantId, workloadId, request.purposeCode(),
                request.description(), request.scopes(), request.maxValiditySeconds(), audit.currentActor()));
    }

    @GetMapping
    public ResponseEntity<List<ConsentPurposeService.PurposeView>> list(@PathVariable String tenantId,
                                                                        @PathVariable UUID workloadId) {
        return ResponseEntity.ok(purposes.list(tenantId, workloadId));
    }

    @PostMapping("/{purposeId}/retire")
    public ResponseEntity<ConsentPurposeService.PurposeView> retire(@PathVariable String tenantId,
                                                                    @PathVariable UUID workloadId,
                                                                    @PathVariable UUID purposeId) {
        return ResponseEntity.ok(purposes.retire(tenantId, workloadId, purposeId, audit.currentActor()));
    }
}
