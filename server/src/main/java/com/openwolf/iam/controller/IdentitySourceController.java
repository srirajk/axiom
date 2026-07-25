package com.openwolf.iam.controller;

import com.openwolf.iam.dto.CreateExternalIdentityLinkRequest;
import com.openwolf.iam.dto.CreateIdentitySourceRequest;
import com.openwolf.iam.dto.ExternalIdentityLinkResponse;
import com.openwolf.iam.dto.IdentitySourceResponse;
import com.openwolf.iam.dto.RotateIdentitySourceSecretRequest;
import com.openwolf.iam.dto.ValidateIdentitySourceResponse;
import com.openwolf.iam.service.IdentitySourceService;
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

@RestController
@RequestMapping("/admin/tenants/{tenantId}/identity-sources")
@PreAuthorize("hasAnyRole('platform_admin','tenant_admin')")
public class IdentitySourceController {
    private final IdentitySourceService service;

    public IdentitySourceController(IdentitySourceService service) { this.service = service; }

    @GetMapping
    public ResponseEntity<List<IdentitySourceResponse>> list(@PathVariable String tenantId) { return ResponseEntity.ok(service.list(tenantId)); }

    @PostMapping
    public ResponseEntity<IdentitySourceResponse> create(@PathVariable String tenantId,
                                                         @Valid @RequestBody CreateIdentitySourceRequest request,
                                                         HttpServletRequest httpRequest) {
        return ResponseEntity.status(201).body(service.create(tenantId, request, httpRequest));
    }

    @GetMapping("/{sourceId}")
    public ResponseEntity<IdentitySourceResponse> get(@PathVariable String tenantId, @PathVariable UUID sourceId) { return ResponseEntity.ok(service.get(tenantId, sourceId)); }

    @PostMapping("/{sourceId}/validate")
    public ResponseEntity<ValidateIdentitySourceResponse> validate(@PathVariable String tenantId, @PathVariable UUID sourceId, HttpServletRequest httpRequest) { return ResponseEntity.ok(service.validate(tenantId, sourceId, httpRequest)); }

    @PostMapping("/{sourceId}/activate")
    public ResponseEntity<IdentitySourceResponse> activate(@PathVariable String tenantId, @PathVariable UUID sourceId, HttpServletRequest httpRequest) { return ResponseEntity.ok(service.activate(tenantId, sourceId, httpRequest)); }

    @PostMapping("/{sourceId}/disable")
    public ResponseEntity<Void> disable(@PathVariable String tenantId, @PathVariable UUID sourceId, HttpServletRequest httpRequest) { throw new ResourceConflictException("approval required for identity-source disable"); }

    @PostMapping("/{sourceId}/rotate-secret")
    public ResponseEntity<Void> rotateSecret(@PathVariable String tenantId, @PathVariable UUID sourceId,
                                             @Valid @RequestBody RotateIdentitySourceSecretRequest request,
                                             HttpServletRequest httpRequest) { throw new ResourceConflictException("approval required for identity-source secret rotation"); }

    @GetMapping("/{sourceId}/links")
    public ResponseEntity<List<ExternalIdentityLinkResponse>> links(@PathVariable String tenantId, @PathVariable UUID sourceId) { return ResponseEntity.ok(service.listLinks(tenantId, sourceId)); }

    @PostMapping("/{sourceId}/links")
    public ResponseEntity<ExternalIdentityLinkResponse> link(@PathVariable String tenantId, @PathVariable UUID sourceId,
                                                             @Valid @RequestBody CreateExternalIdentityLinkRequest request,
                                                             HttpServletRequest httpRequest) { return ResponseEntity.status(201).body(service.link(tenantId, sourceId, request, httpRequest)); }

    @DeleteMapping("/{sourceId}/links/{linkId}")
    public ResponseEntity<Void> disableLink(@PathVariable String tenantId, @PathVariable UUID sourceId,
                                            @PathVariable UUID linkId, HttpServletRequest httpRequest) { service.disableLink(tenantId, sourceId, linkId, httpRequest); return ResponseEntity.noContent().build(); }
}
