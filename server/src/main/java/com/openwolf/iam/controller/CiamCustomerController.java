package com.openwolf.iam.controller;

import com.openwolf.iam.dto.CiamContracts.CompleteRecoveryRequest;
import com.openwolf.iam.dto.CiamContracts.CustomerAuthenticationRequest;
import com.openwolf.iam.dto.CiamContracts.CustomerResponse;
import com.openwolf.iam.dto.CiamContracts.CustomerTokenResponse;
import com.openwolf.iam.dto.CiamContracts.RecoveryChallengeRequest;
import com.openwolf.iam.dto.CiamContracts.RecoveryChallengeResponse;
import com.openwolf.iam.dto.CiamContracts.RegisterCustomerRequest;
import com.openwolf.iam.dto.CiamContracts.RegistrationResponse;
import com.openwolf.iam.dto.CiamContracts.TokenRequest;
import com.openwolf.iam.service.CiamCustomerService;
import com.openwolf.iam.service.CiamCustomerTokenService;
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

import java.util.UUID;

@RestController
@RequestMapping("/ciam/tenants/{tenantId}/customers")
public class CiamCustomerController {
    private final CiamCustomerService customers;
    private final CiamCustomerTokenService tokens;

    public CiamCustomerController(CiamCustomerService customers, CiamCustomerTokenService tokens) {
        this.customers = customers;
        this.tokens = tokens;
    }

    @PostMapping("/registrations")
    public ResponseEntity<RegistrationResponse> register(@PathVariable String tenantId,
                                                          @Valid @RequestBody RegisterCustomerRequest request,
                                                          HttpServletRequest httpRequest) {
        return ResponseEntity.status(201).body(customers.register(tenantId, request.email(),
                request.displayName(), request.password(), correlation(httpRequest)));
    }

    @PostMapping("/verifications")
    public ResponseEntity<CustomerResponse> verify(@PathVariable String tenantId,
                                                    @Valid @RequestBody TokenRequest request,
                                                    HttpServletRequest httpRequest) {
        return ResponseEntity.ok(customers.verify(tenantId, request.token(), correlation(httpRequest)));
    }

    @PostMapping("/recovery-challenges")
    public ResponseEntity<RecoveryChallengeResponse> recoveryChallenge(
            @PathVariable String tenantId, @Valid @RequestBody RecoveryChallengeRequest request,
            HttpServletRequest httpRequest) {
        return ResponseEntity.accepted().body(customers.requestRecovery(
                tenantId, request.email(), correlation(httpRequest)));
    }

    @PostMapping("/recoveries")
    public ResponseEntity<CustomerResponse> recover(@PathVariable String tenantId,
                                                     @Valid @RequestBody CompleteRecoveryRequest request,
                                                     HttpServletRequest httpRequest) {
        return ResponseEntity.ok(customers.recover(tenantId, request.token(), request.newPassword(),
                correlation(httpRequest)));
    }

    @PostMapping("/tokens")
    public ResponseEntity<CustomerTokenResponse> token(@PathVariable String tenantId,
                                                       @Valid @RequestBody CustomerAuthenticationRequest request,
                                                       HttpServletRequest httpRequest) {
        return ResponseEntity.ok(tokens.issue(tenantId, request.email(), request.password(),
                request.clientId(), request.scopes(), correlation(httpRequest)));
    }

    @GetMapping("/{customerId}")
    @PreAuthorize("(hasRole('platform_admin') or (hasRole('tenant_admin') and "
            + "#tenantId == authentication.token.claims['tenant_id'])) or "
            + "(authentication.name == #customerId.toString() and "
            + "#tenantId == authentication.token.claims['tenant_id'])")
    public ResponseEntity<CustomerResponse> get(@PathVariable String tenantId,
                                                 @PathVariable UUID customerId) {
        return ResponseEntity.ok(customers.get(tenantId, customerId));
    }

    private static String correlation(HttpServletRequest request) {
        return request == null ? null : request.getHeader("X-Correlation-ID");
    }
}
