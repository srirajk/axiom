package com.openwolf.iam.controller;

import com.openwolf.iam.dto.AgentExchangeContracts.AgentExchangeRouteResponse;
import com.openwolf.iam.dto.AgentExchangeContracts.CreateAgentExchangeRouteRequest;
import com.openwolf.iam.dto.AgentExchangeContracts.RegisterTrustedBrokerRequest;
import com.openwolf.iam.dto.AgentExchangeContracts.TrustedBrokerResponse;
import com.openwolf.iam.service.AgentExchangeAuthorityService;
import com.openwolf.iam.service.AuditService;
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
@RequestMapping("/admin/tenants/{tenantId}/agent-exchange")
@PreAuthorize("hasRole('platform_admin') or (hasRole('tenant_admin') and "
        + "#tenantId == authentication.token.claims['tenant_id'])")
public class AgentExchangeAuthorityController {
    private final AgentExchangeAuthorityService authority;
    private final AuditService audit;

    public AgentExchangeAuthorityController(AgentExchangeAuthorityService authority, AuditService audit) {
        this.authority = authority;
        this.audit = audit;
    }

    @PostMapping("/brokers")
    public ResponseEntity<TrustedBrokerResponse> registerBroker(
            @PathVariable String tenantId, @Valid @RequestBody RegisterTrustedBrokerRequest request,
            HttpServletRequest httpRequest) {
        return ResponseEntity.status(201).body(authority.registerBroker(tenantId, request,
                audit.currentActor(), correlation(httpRequest)));
    }

    @GetMapping("/brokers")
    public ResponseEntity<List<TrustedBrokerResponse>> listBrokers(@PathVariable String tenantId) {
        return ResponseEntity.ok(authority.listBrokers(tenantId));
    }

    @PostMapping("/brokers/{brokerId}/revoke")
    public ResponseEntity<TrustedBrokerResponse> revokeBroker(
            @PathVariable String tenantId, @PathVariable UUID brokerId, HttpServletRequest httpRequest) {
        return ResponseEntity.ok(authority.revokeBroker(tenantId, brokerId,
                audit.currentActor(), correlation(httpRequest)));
    }

    @PostMapping("/routes")
    public ResponseEntity<AgentExchangeRouteResponse> createRoute(
            @PathVariable String tenantId, @Valid @RequestBody CreateAgentExchangeRouteRequest request,
            HttpServletRequest httpRequest) {
        return ResponseEntity.status(201).body(authority.createRoute(tenantId, request,
                audit.currentActor(), correlation(httpRequest)));
    }

    @GetMapping("/routes")
    public ResponseEntity<List<AgentExchangeRouteResponse>> listRoutes(@PathVariable String tenantId) {
        return ResponseEntity.ok(authority.listRoutes(tenantId));
    }

    @PostMapping("/routes/{routeId}/revoke")
    public ResponseEntity<AgentExchangeRouteResponse> revokeRoute(
            @PathVariable String tenantId, @PathVariable UUID routeId, HttpServletRequest httpRequest) {
        return ResponseEntity.ok(authority.revokeRoute(tenantId, routeId,
                audit.currentActor(), correlation(httpRequest)));
    }

    private static String correlation(HttpServletRequest request) {
        return request == null ? null : request.getHeader("X-Correlation-ID");
    }
}
