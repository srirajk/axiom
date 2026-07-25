package com.openwolf.iam.controller;

import com.openwolf.iam.service.SigningKeyLifecycleService;
import com.openwolf.iam.exception.ResourceConflictException;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.UUID;

@RestController
@RequestMapping("/admin/tenants/{tenantId}/signing-keys")
@PreAuthorize("hasAnyRole('platform_admin','tenant_admin')")
public class SigningKeyController {
    private final SigningKeyLifecycleService service;
    public SigningKeyController(SigningKeyLifecycleService service) { this.service = service; }

    @GetMapping public List<SigningKeyLifecycleService.SigningKeyView> list(@PathVariable String tenantId) { return service.list(tenantId); }
    @PostMapping public ResponseEntity<SigningKeyLifecycleService.SigningKeyView> create(@PathVariable String tenantId, HttpServletRequest request) { return ResponseEntity.status(201).body(service.createStaged(tenantId, request)); }
    @PostMapping("/{id}/activate") public SigningKeyLifecycleService.SigningKeyView activate(@PathVariable String tenantId, @PathVariable UUID id, HttpServletRequest request) { return service.activate(tenantId, id, request); }
    @PostMapping("/{id}/retire") public ResponseEntity<Void> retire(@PathVariable String tenantId, @PathVariable UUID id, HttpServletRequest request) { service.retire(tenantId, id, request); return ResponseEntity.noContent().build(); }
    @PostMapping("/{id}/emergency-retire")
    @PreAuthorize("hasRole('platform_admin')")
    public ResponseEntity<Void> emergencyRetire(@PathVariable String tenantId, @PathVariable UUID id, HttpServletRequest request) { throw new ResourceConflictException("approval required for signing-key emergency retirement"); }
}
