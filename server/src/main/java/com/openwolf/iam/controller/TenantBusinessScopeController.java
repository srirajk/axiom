package com.openwolf.iam.controller;

import com.openwolf.iam.scopes.TenantBusinessScopeService;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Tenant-scoped approved custom business scopes (Axiom management API). POST registers a name (201 created; 200 for an
 * identical repeat); GET lists the deployment-configured baseline and the tenant's catalog. No delete/disable endpoint.
 */
@RestController
@RequestMapping("/admin/tenants/{tenantId}/business-scopes")
@PreAuthorize("hasAnyRole('platform_admin','tenant_admin')")
public class TenantBusinessScopeController {
    public record RegisterBusinessScopeRequest(String scope, String description) {}

    private final TenantBusinessScopeService service;

    public TenantBusinessScopeController(TenantBusinessScopeService service) {
        this.service = service;
    }

    @PostMapping
    public ResponseEntity<TenantBusinessScopeService.ScopeResponse> register(
            @PathVariable String tenantId, @RequestBody RegisterBusinessScopeRequest request, HttpServletRequest http) {
        TenantBusinessScopeService.Registration registration = service.register(tenantId,
                request == null ? null : request.scope(), request == null ? null : request.description(),
                http.getHeader("X-Correlation-ID"));
        return ResponseEntity.status(registration.created() ? 201 : 200).body(registration.scope());
    }

    @GetMapping
    public ResponseEntity<TenantBusinessScopeService.CatalogResponse> list(@PathVariable String tenantId) {
        return ResponseEntity.ok(service.list(tenantId));
    }
}
