package com.openwolf.iam.authority;

import com.openwolf.iam.authority.standing.StandingGrantService;
import com.openwolf.iam.authority.task.DurableTaskService;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.Instant;
import java.util.List;
import java.util.Set;
import java.util.UUID;

/** Phase 3.3/3.4 owner self-service: approve and withdraw standing grants, cancel work running on one's behalf. */
@RestController
@RequestMapping("/api/me")
public class OwnerAuthorityController {
    public record ApproveStandingGrantRequest(@NotNull UUID agentWorkloadId, @NotBlank @Size(max = 512) String audience,
                                              @NotEmpty Set<@NotBlank @Size(max = 120) String> scopes,
                                              @NotBlank @Size(max = 500) String purpose, @NotNull Instant expiresAt) {}

    public record ReasonRequest(@Size(max = 200) String reason) {}

    private final StandingGrantService grants;
    private final DurableTaskService tasks;

    public OwnerAuthorityController(StandingGrantService grants, DurableTaskService tasks) {
        this.grants = grants;
        this.tasks = tasks;
    }

    @PostMapping("/standing-grants")
    public ResponseEntity<StandingGrantService.GrantView> approve(@AuthenticationPrincipal Jwt owner,
                                                                  @Valid @RequestBody ApproveStandingGrantRequest request) {
        return ResponseEntity.status(201).body(grants.approve(owner, request.agentWorkloadId(), request.audience(),
                request.scopes(), request.purpose(), request.expiresAt()));
    }

    @GetMapping("/standing-grants")
    public ResponseEntity<List<StandingGrantService.GrantView>> list(@AuthenticationPrincipal Jwt owner) {
        return ResponseEntity.ok(grants.listForOwner(owner));
    }

    @PostMapping("/standing-grants/{grantId}/revoke")
    public ResponseEntity<StandingGrantService.GrantView> revoke(@AuthenticationPrincipal Jwt owner,
                                                                 @PathVariable UUID grantId,
                                                                 @Valid @RequestBody(required = false) ReasonRequest request) {
        return ResponseEntity.ok(grants.revokeByOwner(owner, grantId, request == null ? null : request.reason()));
    }

    @PostMapping("/tasks/{taskId}/cancel")
    public ResponseEntity<DurableTaskService.TaskView> cancelTask(@AuthenticationPrincipal Jwt owner,
                                                                  @PathVariable UUID taskId,
                                                                  @Valid @RequestBody(required = false) ReasonRequest request) {
        return ResponseEntity.ok(tasks.cancelByOwner(owner.getClaimAsString("tenant_id"), owner.getSubject(), taskId,
                request == null ? null : request.reason()));
    }
}
