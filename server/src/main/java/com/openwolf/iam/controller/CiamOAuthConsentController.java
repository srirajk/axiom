package com.openwolf.iam.controller;

import com.openwolf.iam.service.CustomerOAuthConsentService;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.UUID;

/**
 * Customer self-service for OAuth application consents (Axiom-specific management API; the consent itself is the
 * standard OAuth authorization consent). Customer tokens only: the path's customer must be the authenticated customer.
 */
@RestController
@RequestMapping("/ciam/tenants/{tenantId}/customers/{customerId}/oauth-consents")
@PreAuthorize("authentication.name == #customerId.toString() and #tenantId == authentication.token.claims['tenant_id']")
public class CiamOAuthConsentController {
    private final CustomerOAuthConsentService service;

    public CiamOAuthConsentController(CustomerOAuthConsentService service) {
        this.service = service;
    }

    @GetMapping
    public ResponseEntity<List<CustomerOAuthConsentService.ConsentResponse>> list(@PathVariable String tenantId,
                                                                                  @PathVariable UUID customerId) {
        return ResponseEntity.ok(service.list(tenantId, customerId));
    }

    @DeleteMapping("/{clientId}")
    public ResponseEntity<CustomerOAuthConsentService.ConsentResponse> withdraw(
            @PathVariable String tenantId, @PathVariable UUID customerId, @PathVariable String clientId,
            HttpServletRequest request) {
        return ResponseEntity.ok(service.withdraw(tenantId, customerId, clientId, request.getHeader("X-Correlation-ID")));
    }
}
