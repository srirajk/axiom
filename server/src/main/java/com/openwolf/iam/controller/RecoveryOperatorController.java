package com.openwolf.iam.controller;

import com.openwolf.iam.dto.EnrollRecoveryOperatorRequest;
import com.openwolf.iam.dto.RecoveryOperatorResponse;
import com.openwolf.iam.dto.RecoveryOperatorTransitionRequest;
import com.openwolf.iam.service.RecoveryOperatorService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.UUID;

@RestController
@RequestMapping("/admin/tenants/{tenantId}/recovery-operators")
@PreAuthorize("hasAnyRole('platform_admin','tenant_admin')")
public class RecoveryOperatorController {
    private final RecoveryOperatorService service;
    public RecoveryOperatorController(RecoveryOperatorService service) { this.service = service; }

    @GetMapping public ResponseEntity<List<RecoveryOperatorResponse>> list(@PathVariable String tenantId) {
        return ResponseEntity.ok(service.list(tenantId));
    }

    @PostMapping public ResponseEntity<RecoveryOperatorResponse> enroll(@PathVariable String tenantId,
            @Valid @RequestBody EnrollRecoveryOperatorRequest request, HttpServletRequest httpRequest) {
        return ResponseEntity.status(201).body(service.enroll(tenantId, request, httpRequest));
    }

    @PostMapping("/{operatorId}/rotate")
    public ResponseEntity<RecoveryOperatorResponse> rotate(@PathVariable String tenantId, @PathVariable UUID operatorId,
            @Valid @RequestBody RecoveryOperatorTransitionRequest request, HttpServletRequest httpRequest) {
        return ResponseEntity.ok(service.rotate(tenantId, operatorId, request, httpRequest));
    }

    @PostMapping("/{operatorId}/disable")
    public ResponseEntity<RecoveryOperatorResponse> disable(@PathVariable String tenantId, @PathVariable UUID operatorId,
            @Valid @RequestBody RecoveryOperatorTransitionRequest request, HttpServletRequest httpRequest) {
        return ResponseEntity.ok(service.disable(tenantId, operatorId, request, httpRequest));
    }

}
