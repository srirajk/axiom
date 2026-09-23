package com.openwolf.iam.controller;

import com.openwolf.iam.dto.CiamContracts.AgentWorkloadConsentOption;
import com.openwolf.iam.service.CiamDelegationService;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
@RequestMapping("/ciam/tenants/{tenantId}/agent-workloads")
@PreAuthorize("authentication.token.claims['identity_kind'] == 'customer'"
        + " and #tenantId == authentication.token.claims['tenant_id']")
public class CiamCustomerWorkloadController {
    private final CiamDelegationService service;

    public CiamCustomerWorkloadController(CiamDelegationService service) {
        this.service = service;
    }

    @GetMapping
    public ResponseEntity<List<AgentWorkloadConsentOption>> list(@PathVariable String tenantId) {
        return ResponseEntity.ok(service.listConsentOptions(tenantId));
    }
}
