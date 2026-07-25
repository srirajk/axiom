package com.openwolf.iam.controller;

import com.openwolf.iam.dto.IdentityControlProposalRequest;
import com.openwolf.iam.dto.IdentityControlRequestResponse;
import com.openwolf.iam.dto.IdentityControlTransitionRequest;
import com.openwolf.iam.entity.IdentityControlRequest;
import com.openwolf.iam.service.IdentityControlRequestService;
import com.openwolf.iam.service.IdentityControlApplyService;
import com.openwolf.iam.dto.IdentityControlApplyResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import org.springframework.data.domain.Page;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.UUID;

@RestController
@RequestMapping("/admin/tenants/{tenantId}/identity-control-requests")
@PreAuthorize("hasAnyRole('platform_admin','tenant_admin')")
public class IdentityControlRequestController {
    private final IdentityControlRequestService service;
    private final IdentityControlApplyService applyService;
    public IdentityControlRequestController(IdentityControlRequestService service, IdentityControlApplyService applyService) {
        this.service = service;
        this.applyService = applyService;
    }

    @PostMapping
    public ResponseEntity<IdentityControlRequestResponse> propose(@PathVariable String tenantId,
            @Valid @RequestBody IdentityControlProposalRequest request, HttpServletRequest httpRequest) {
        return ResponseEntity.status(201).body(service.propose(tenantId, request, httpRequest));
    }

    @GetMapping
    public ResponseEntity<Page<IdentityControlRequestResponse>> list(@PathVariable String tenantId,
            @RequestParam(required = false) IdentityControlRequest.Status status,
            @RequestParam(defaultValue = "0") int page, @RequestParam(defaultValue = "50") int size) {
        return ResponseEntity.ok(service.list(tenantId, status, page, size));
    }

    @GetMapping("/{requestId}")
    public ResponseEntity<IdentityControlRequestResponse> get(@PathVariable String tenantId, @PathVariable UUID requestId) {
        return ResponseEntity.ok(service.get(tenantId, requestId));
    }

    @PostMapping("/{requestId}/approve")
    public ResponseEntity<IdentityControlRequestResponse> approve(@PathVariable String tenantId, @PathVariable UUID requestId,
            @Valid @RequestBody IdentityControlTransitionRequest request, HttpServletRequest httpRequest) {
        return ResponseEntity.ok(service.approve(tenantId, requestId, request, httpRequest));
    }

    @PostMapping("/{requestId}/reject")
    public ResponseEntity<IdentityControlRequestResponse> reject(@PathVariable String tenantId, @PathVariable UUID requestId,
            @Valid @RequestBody IdentityControlTransitionRequest request, HttpServletRequest httpRequest) {
        return ResponseEntity.ok(service.reject(tenantId, requestId, request, httpRequest));
    }

    @PostMapping("/{requestId}/cancel")
    public ResponseEntity<IdentityControlRequestResponse> cancel(@PathVariable String tenantId, @PathVariable UUID requestId,
            @Valid @RequestBody IdentityControlTransitionRequest request, HttpServletRequest httpRequest) {
        return ResponseEntity.ok(service.cancel(tenantId, requestId, request, httpRequest));
    }

    @PostMapping("/{requestId}/apply")
    public ResponseEntity<IdentityControlApplyResponse> apply(@PathVariable String tenantId, @PathVariable UUID requestId,
            @Valid @RequestBody IdentityControlTransitionRequest request, HttpServletRequest httpRequest) {
        return ResponseEntity.ok(applyService.apply(tenantId, requestId, request.expectedRevision(), httpRequest));
    }
}
