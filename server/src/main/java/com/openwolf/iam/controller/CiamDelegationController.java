package com.openwolf.iam.controller;

import com.openwolf.iam.dto.CiamContracts.CreateDelegationGrantRequest;
import com.openwolf.iam.dto.CiamContracts.DelegationGrantResponse;
import com.openwolf.iam.dto.CiamContracts.RevokeDelegationGrantRequest;
import com.openwolf.iam.service.AuditService;
import com.openwolf.iam.service.CiamDelegationService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
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

@RestController
@RequestMapping("/ciam/tenants/{tenantId}/customers/{customerId}/delegation-grants")
@PreAuthorize("(hasRole('platform_admin') or (hasRole('tenant_admin') and "
        + "#tenantId == authentication.token.claims['tenant_id'])) or "
        + "(authentication.name == #customerId.toString() and "
        + "#tenantId == authentication.token.claims['tenant_id'])")
public class CiamDelegationController {
    private final CiamDelegationService service;
    private final AuditService audit;

    public CiamDelegationController(CiamDelegationService service, AuditService audit) {
        this.service = service;
        this.audit = audit;
    }

    @GetMapping
    public ResponseEntity<List<DelegationGrantResponse>> list(@PathVariable String tenantId,
                                                               @PathVariable UUID customerId) {
        return ResponseEntity.ok(service.listGrants(tenantId, customerId));
    }

    @PostMapping
    public ResponseEntity<DelegationGrantResponse> create(
            @PathVariable String tenantId, @PathVariable UUID customerId,
            @Valid @RequestBody CreateDelegationGrantRequest request, HttpServletRequest httpRequest) {
        return ResponseEntity.status(201).body(service.createGrant(tenantId, customerId,
                request.agentWorkloadId(), request.audience(), request.scopes(), request.purpose(),
                request.expiresAt(), audit.currentActor(), correlation(httpRequest)));
    }

    @PostMapping("/{grantId}/revoke")
    public ResponseEntity<DelegationGrantResponse> revoke(
            @PathVariable String tenantId, @PathVariable UUID customerId, @PathVariable UUID grantId,
            @Valid @RequestBody RevokeDelegationGrantRequest request, HttpServletRequest httpRequest) {
        return ResponseEntity.ok(service.revokeGrant(tenantId, customerId, grantId, request.reason(),
                audit.currentActor(), correlation(httpRequest)));
    }

    private static String correlation(HttpServletRequest request) {
        return request == null ? null : request.getHeader("X-Correlation-ID");
    }
}
