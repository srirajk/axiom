package com.openwolf.iam.authority.approval;

import com.fasterxml.jackson.databind.JsonNode;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Positive;
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

import java.util.List;
import java.util.Set;
import java.util.UUID;

/** Phase 3.7–3.9 approval workflow for people (Axiom API tokens only; the Agent never calls this API). */
@RestController
@RequestMapping("/api/v1/action-approvals")
public class ActionApprovalController {
    public record RequestApproval(@NotNull UUID agentWorkloadId, @NotBlank @Size(max = 512) String receiverAudience,
                                  @NotEmpty Set<@NotBlank @Size(max = 120) String> scopes,
                                  @NotBlank @Size(max = 64) String actionType, @NotNull JsonNode action,
                                  @Positive long deadlineSeconds, List<@NotBlank String> requiredAcr,
                                  @Positive int maxAuthAgeSeconds) {}

    public record DigestRequest(@NotBlank @Size(max = 64) String actionDigest) {}

    public record ReasonRequest(@Size(max = 200) String reason) {}

    private final ActionApprovalService approvals;

    public ActionApprovalController(ActionApprovalService approvals) {
        this.approvals = approvals;
    }

    @PostMapping
    public ResponseEntity<ActionApprovalService.ApprovalView> request(@AuthenticationPrincipal Jwt caller,
                                                                     @Valid @RequestBody RequestApproval r) {
        return ResponseEntity.status(201).body(approvals.request(caller, r.agentWorkloadId(), r.receiverAudience(),
                r.scopes(), r.actionType(), r.action(), r.deadlineSeconds(), r.requiredAcr(), r.maxAuthAgeSeconds()));
    }

    @GetMapping("/{id}")
    public ResponseEntity<ActionApprovalService.ApprovalView> get(@AuthenticationPrincipal Jwt caller, @PathVariable UUID id) {
        return ResponseEntity.ok(approvals.get(caller.getClaimAsString("tenant_id"), id, caller.getSubject(), false));
    }

    @PostMapping("/{id}/approve")
    public ResponseEntity<ActionApprovalService.ApprovalView> approve(@AuthenticationPrincipal Jwt caller,
                                                                     @PathVariable UUID id,
                                                                     @Valid @RequestBody DigestRequest r) {
        return ResponseEntity.ok(approvals.approve(caller, id, r.actionDigest()));
    }

    @PostMapping("/{id}/reject")
    public ResponseEntity<ActionApprovalService.ApprovalView> reject(@AuthenticationPrincipal Jwt caller,
                                                                    @PathVariable UUID id,
                                                                    @Valid @RequestBody(required = false) ReasonRequest r) {
        return ResponseEntity.ok(approvals.reject(caller, id, r == null ? null : r.reason()));
    }

    @PostMapping("/{id}/confirm")
    public ResponseEntity<ActionApprovalService.ApprovalView> confirm(@AuthenticationPrincipal Jwt caller,
                                                                     @PathVariable UUID id,
                                                                     @Valid @RequestBody DigestRequest r) {
        return ResponseEntity.ok(approvals.confirm(caller, id, r.actionDigest()));
    }

    @PostMapping("/{id}/revoke")
    public ResponseEntity<ActionApprovalService.ApprovalView> revoke(@AuthenticationPrincipal Jwt caller,
                                                                    @PathVariable UUID id,
                                                                    @Valid @RequestBody(required = false) ReasonRequest r) {
        return ResponseEntity.ok(approvals.revoke(caller.getClaimAsString("tenant_id"), id, caller.getSubject(), false,
                r == null ? null : r.reason()));
    }
}
