package com.openwolf.iam.controller;

import com.openwolf.iam.dto.CiamContracts.AgentWorkloadResponse;
import com.openwolf.iam.dto.CiamContracts.CustomerResponse;
import com.openwolf.iam.dto.CiamContracts.RegisterAgentWorkloadRequest;
import com.openwolf.iam.dto.CiamContracts.DelegationGrantResponse;
import com.openwolf.iam.dto.CiamContracts.CiamLifecycleEventResponse;
import com.openwolf.iam.service.AuditService;
import com.openwolf.iam.service.CiamCustomerService;
import com.openwolf.iam.service.CiamDelegationService;
import com.openwolf.iam.service.CiamLifecycleAuditService;
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
@RequestMapping("/admin/tenants/{tenantId}/ciam")
@PreAuthorize("hasRole('platform_admin') or (hasRole('tenant_admin') and "
        + "#tenantId == authentication.token.claims['tenant_id'])")
public class CiamAdminController {
    private final CiamDelegationService delegations;
    private final CiamCustomerService customers;
    private final AuditService audit;
    private final CiamLifecycleAuditService lifecycleAudit;

    public CiamAdminController(CiamDelegationService delegations, CiamCustomerService customers,
                               AuditService audit, CiamLifecycleAuditService lifecycleAudit) {
        this.delegations = delegations;
        this.customers = customers;
        this.audit = audit;
        this.lifecycleAudit = lifecycleAudit;
    }

    @PostMapping("/agent-workloads")
    public ResponseEntity<AgentWorkloadResponse> registerWorkload(
            @PathVariable String tenantId, @Valid @RequestBody RegisterAgentWorkloadRequest request,
            HttpServletRequest httpRequest) {
        return ResponseEntity.status(201).body(delegations.registerWorkload(tenantId,
                request.workloadRef(), request.name(), request.oauthClientId(), audit.currentActor(),
                correlation(httpRequest)));
    }

    @GetMapping("/agent-workloads")
    public ResponseEntity<List<AgentWorkloadResponse>> listWorkloads(@PathVariable String tenantId) {
        return ResponseEntity.ok(delegations.listWorkloads(tenantId));
    }

    @GetMapping("/customers")
    public ResponseEntity<List<CustomerResponse>> listCustomers(@PathVariable String tenantId) {
        return ResponseEntity.ok(customers.list(tenantId));
    }

    @GetMapping("/delegation-grants")
    public ResponseEntity<List<DelegationGrantResponse>> listGrants(@PathVariable String tenantId) {
        return ResponseEntity.ok(delegations.listAllGrants(tenantId));
    }

    @GetMapping("/events")
    public ResponseEntity<List<CiamLifecycleEventResponse>> listEvents(@PathVariable String tenantId) {
        return ResponseEntity.ok(lifecycleAudit.list(tenantId));
    }

    @PostMapping("/agent-workloads/{workloadId}/revoke")
    public ResponseEntity<AgentWorkloadResponse> revokeWorkload(
            @PathVariable String tenantId, @PathVariable UUID workloadId, HttpServletRequest httpRequest) {
        return ResponseEntity.ok(delegations.revokeWorkload(tenantId, workloadId, audit.currentActor(),
                correlation(httpRequest)));
    }

    @PostMapping("/customers/{customerId}/suspend")
    public ResponseEntity<CustomerResponse> suspend(@PathVariable String tenantId,
                                                     @PathVariable UUID customerId,
                                                     HttpServletRequest httpRequest) {
        return ResponseEntity.ok(customers.suspend(tenantId, customerId, audit.currentActor(),
                correlation(httpRequest)));
    }

    @PostMapping("/customers/{customerId}/reactivate")
    public ResponseEntity<CustomerResponse> reactivate(@PathVariable String tenantId,
                                                        @PathVariable UUID customerId,
                                                        HttpServletRequest httpRequest) {
        return ResponseEntity.ok(customers.reactivate(tenantId, customerId, audit.currentActor(),
                correlation(httpRequest)));
    }

    private static String correlation(HttpServletRequest request) {
        return request == null ? null : request.getHeader("X-Correlation-ID");
    }
}
