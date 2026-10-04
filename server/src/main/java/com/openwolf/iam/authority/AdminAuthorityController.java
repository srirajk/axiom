package com.openwolf.iam.authority;

import com.openwolf.iam.authority.standing.StandingGrantService;
import com.openwolf.iam.authority.task.DurableTaskService;
import com.openwolf.iam.service.AuditService;
import jakarta.validation.Valid;
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

/** Tenant administrators can see and withdraw standing grants and cancel tasks; they can never approve a grant. */
@RestController
@RequestMapping("/admin/tenants/{tenantId}")
@PreAuthorize("hasRole('platform_admin') or (hasRole('tenant_admin') and "
        + "#tenantId == authentication.token.claims['tenant_id'])")
public class AdminAuthorityController {
    public record ReasonRequest(@Size(max = 200) String reason) {}

    private final StandingGrantService grants;
    private final DurableTaskService tasks;
    private final AuditService audit;

    public AdminAuthorityController(StandingGrantService grants, DurableTaskService tasks, AuditService audit) {
        this.grants = grants;
        this.tasks = tasks;
        this.audit = audit;
    }

    @GetMapping("/standing-grants")
    public ResponseEntity<List<StandingGrantService.GrantView>> list(@PathVariable String tenantId) {
        return ResponseEntity.ok(grants.list(tenantId));
    }

    @PostMapping("/standing-grants/{grantId}/revoke")
    public ResponseEntity<StandingGrantService.GrantView> revoke(@PathVariable String tenantId, @PathVariable UUID grantId,
                                                                 @Valid @RequestBody(required = false) ReasonRequest request) {
        return ResponseEntity.ok(grants.revokeByAdministrator(tenantId, grantId,
                request == null ? null : request.reason(), audit.currentActor()));
    }

    @PostMapping("/tasks/{taskId}/cancel")
    public ResponseEntity<DurableTaskService.TaskView> cancelTask(@PathVariable String tenantId, @PathVariable UUID taskId,
                                                                  @Valid @RequestBody(required = false) ReasonRequest request) {
        return ResponseEntity.ok(tasks.cancelByAdministrator(tenantId, taskId,
                request == null ? null : request.reason(), audit.currentActor()));
    }
}
