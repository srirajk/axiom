package com.openwolf.iam.controller;

import com.openwolf.iam.dto.CreatedTenantApplicationClientResponse;
import com.openwolf.iam.dto.CreateTenantApplicationClientRequest;
import com.openwolf.iam.dto.CreateTenantApplicationRequest;
import com.openwolf.iam.dto.RevokeTenantApplicationClientRequest;
import com.openwolf.iam.dto.RotateTenantApplicationClientSecretRequest;
import com.openwolf.iam.dto.TenantApplicationClientResponse;
import com.openwolf.iam.dto.TenantApplicationResponse;
import com.openwolf.iam.service.TenantApplicationService;
import com.openwolf.iam.exception.ResourceConflictException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.UUID;

/** AXP-1 tenant application/client lifecycle; Axiom Admin's system client is intentionally absent. */
@RestController
@RequestMapping("/admin/tenants/{tenantId}/applications")
public class TenantApplicationController {
    private final TenantApplicationService service;
    public TenantApplicationController(TenantApplicationService service) { this.service = service; }

    @GetMapping
    @PreAuthorize("hasAnyRole('platform_admin','tenant_admin')")
    public ResponseEntity<List<TenantApplicationResponse>> list(@PathVariable String tenantId) {
        return ResponseEntity.ok(service.list(tenantId));
    }

    @PostMapping
    @PreAuthorize("hasAnyRole('platform_admin','tenant_admin')")
    public ResponseEntity<TenantApplicationResponse> create(@PathVariable String tenantId,
            @Valid @RequestBody CreateTenantApplicationRequest request, HttpServletRequest httpRequest) {
        return ResponseEntity.status(201).body(service.create(tenantId, request, httpRequest));
    }

    @GetMapping("/{applicationId}")
    @PreAuthorize("hasAnyRole('platform_admin','tenant_admin')")
    public ResponseEntity<TenantApplicationResponse> get(@PathVariable String tenantId, @PathVariable UUID applicationId) {
        return ResponseEntity.ok(service.get(tenantId, applicationId));
    }

    @DeleteMapping("/{applicationId}")
    @PreAuthorize("hasAnyRole('platform_admin','tenant_admin')")
    public ResponseEntity<Void> disable(@PathVariable String tenantId, @PathVariable UUID applicationId,
                                        HttpServletRequest httpRequest) {
        service.disableApplication(tenantId, applicationId, httpRequest);
        return ResponseEntity.noContent().build();
    }

    @GetMapping("/{applicationId}/clients")
    @PreAuthorize("hasAnyRole('platform_admin','tenant_admin')")
    public ResponseEntity<List<TenantApplicationClientResponse>> listClients(@PathVariable String tenantId,
                                                                                @PathVariable UUID applicationId) {
        return ResponseEntity.ok(service.listClients(tenantId, applicationId));
    }

    @PostMapping("/{applicationId}/clients")
    @PreAuthorize("hasAnyRole('platform_admin','tenant_admin')")
    public ResponseEntity<CreatedTenantApplicationClientResponse> createClient(@PathVariable String tenantId,
            @PathVariable UUID applicationId, @Valid @RequestBody CreateTenantApplicationClientRequest request,
            HttpServletRequest httpRequest) {
        return ResponseEntity.status(201).body(service.createClient(tenantId, applicationId, request, httpRequest));
    }

    @DeleteMapping("/{applicationId}/clients/{clientId}")
    @PreAuthorize("hasAnyRole('platform_admin','tenant_admin')")
    public ResponseEntity<Void> disableClient(@PathVariable String tenantId, @PathVariable UUID applicationId,
                                               @PathVariable UUID clientId, HttpServletRequest httpRequest) {
        service.disableClient(tenantId, applicationId, clientId, httpRequest);
        return ResponseEntity.noContent().build();
    }

    @PostMapping("/{applicationId}/clients/{clientId}/rotate-secret")
    @PreAuthorize("hasAnyRole('platform_admin','tenant_admin')")
    public ResponseEntity<CreatedTenantApplicationClientResponse> rotateSecret(
            @PathVariable String tenantId, @PathVariable UUID applicationId, @PathVariable UUID clientId,
            @Valid @RequestBody RotateTenantApplicationClientSecretRequest request,
            HttpServletRequest httpRequest) {
        throw new ResourceConflictException("approval required for application-client secret rotation");
    }

    @PostMapping("/{applicationId}/clients/{clientId}/revoke")
    @PreAuthorize("hasAnyRole('platform_admin','tenant_admin')")
    public ResponseEntity<TenantApplicationClientResponse> revokeSecret(
            @PathVariable String tenantId, @PathVariable UUID applicationId, @PathVariable UUID clientId,
            @Valid @RequestBody RevokeTenantApplicationClientRequest request,
            HttpServletRequest httpRequest) {
        throw new ResourceConflictException("approval required for application-client secret revocation");
    }
}
