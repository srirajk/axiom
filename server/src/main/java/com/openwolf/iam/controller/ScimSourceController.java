package com.openwolf.iam.controller;

import com.openwolf.iam.dto.CreateScimSourceRequest;
import com.openwolf.iam.dto.ScimSourceResponse;
import com.openwolf.iam.service.ScimSourceService;
import com.openwolf.iam.service.ScimReconciliationService;
import com.openwolf.iam.dto.ScimReconciliationResponse;
import com.openwolf.iam.exception.ResourceConflictException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.UUID;

@RestController
@RequestMapping("/admin/tenants/{tenantId}/scim-sources")
@PreAuthorize("hasAnyRole('platform_admin','tenant_admin')")
public class ScimSourceController {
    private final ScimSourceService service;
    private final ScimReconciliationService reconciliation;
    public ScimSourceController(ScimSourceService service, ScimReconciliationService reconciliation) { this.service = service; this.reconciliation = reconciliation; }
    @GetMapping public List<ScimSourceResponse> list(@PathVariable String tenantId) { return service.list(tenantId); }
    @PostMapping public ResponseEntity<ScimSourceResponse> create(@PathVariable String tenantId, @Valid @RequestBody CreateScimSourceRequest request, HttpServletRequest httpRequest) { return ResponseEntity.status(201).body(service.create(tenantId, request, httpRequest)); }
    @PostMapping("/{id}/rotate") public ScimSourceResponse rotate(@PathVariable String tenantId, @PathVariable UUID id, HttpServletRequest request) { throw new ResourceConflictException("approval required for SCIM credential rotation"); }
    @PostMapping("/{id}/revoke") public ResponseEntity<Void> revoke(@PathVariable String tenantId, @PathVariable UUID id, HttpServletRequest request) { throw new ResourceConflictException("approval required for SCIM credential revocation"); }
    @GetMapping("/{id}/reconciliation") public ScimReconciliationResponse reconciliation(@PathVariable String tenantId, @PathVariable UUID id, HttpServletRequest request) { return reconciliation.check(tenantId, id, request); }
}
