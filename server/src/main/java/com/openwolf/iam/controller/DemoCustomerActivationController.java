package com.openwolf.iam.controller;

import com.openwolf.iam.dto.CiamContracts.CustomerResponse;
import com.openwolf.iam.entity.CustomerIdentity;
import com.openwolf.iam.entity.CustomerIdentityChallenge;
import com.openwolf.iam.exception.EntityNotFoundException;
import com.openwolf.iam.exception.ResourceConflictException;
import com.openwolf.iam.repository.CustomerIdentityChallengeRepository;
import com.openwolf.iam.repository.CustomerIdentityRepository;
import com.openwolf.iam.service.AuditService;
import com.openwolf.iam.service.CiamLifecycleAuditService;
import jakarta.validation.Valid;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.Size;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.Instant;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/**
 * Explicit local-demo fixture. This simulates verification for administrator-provisioned identities with synthetic
 * email addresses; it never proves control of a real mailbox and must not be enabled for real customer identities.
 */
@RestController
@RequestMapping("/admin/tenants/{tenantId}/ciam/demo-customers")
@ConditionalOnProperty(prefix = "iam.ciam.demo-admin-activation", name = "enabled", havingValue = "true")
public class DemoCustomerActivationController {
    private final CustomerIdentityRepository customers;
    private final CustomerIdentityChallengeRepository challenges;
    private final CiamLifecycleAuditService lifecycleAudit;
    private final AuditService audit;
    private final String allowedTenant;
    private final String allowedDomain;

    public DemoCustomerActivationController(CustomerIdentityRepository customers,
                                            CustomerIdentityChallengeRepository challenges,
                                            CiamLifecycleAuditService lifecycleAudit, AuditService audit,
                                            @Value("${iam.ciam.demo-admin-activation.allowed-tenant:}") String allowedTenant,
                                            @Value("${iam.ciam.demo-admin-activation.allowed-email-domain:}") String allowedDomain,
                                            @Value("${iam.ciam.demo-admin-activation.allowed-issuer:}") String allowedIssuer,
                                            @Value("${spring.security.oauth2.authorizationserver.issuer:}") String issuer) {
        String domain = allowedDomain.trim().toLowerCase(Locale.ROOT);
        if (allowedTenant.isBlank() || allowedIssuer.isBlank() || !allowedIssuer.equals(issuer)
                || !(domain.endsWith(".local") || domain.endsWith(".invalid"))) {
            throw new IllegalStateException("demo customer activation requires an exact issuer, tenant, and synthetic email domain");
        }
        this.customers = customers;
        this.challenges = challenges;
        this.lifecycleAudit = lifecycleAudit;
        this.audit = audit;
        this.allowedTenant = allowedTenant;
        this.allowedDomain = domain;
    }

    public record ActivationRequest(@NotEmpty @Size(max = 20) List<@Email @NotBlank String> emails) {}

    @PostMapping("/activate")
    @PreAuthorize("hasRole('platform_admin')")
    @Transactional
    public ResponseEntity<List<CustomerResponse>> activate(@PathVariable String tenantId,
                                                            @Valid @RequestBody ActivationRequest request) {
        if (!allowedTenant.equals(tenantId)) throw new EntityNotFoundException("demo tenant not found");
        List<CustomerIdentity> selected = new ArrayList<>();
        Set<String> seen = new HashSet<>();
        for (String suppliedEmail : request.emails()) {
            String email = suppliedEmail.trim().toLowerCase(Locale.ROOT);
            if (!seen.add(email) || !email.endsWith("@" + allowedDomain)) {
                throw new ResourceConflictException("demo activation requires distinct synthetic addresses");
            }
            CustomerIdentity customer = customers.findByTenantIdAndEmailIgnoreCase(tenantId, email)
                    .orElseThrow(() -> new EntityNotFoundException("demo customer not found"));
            if (customer.getProvisioningSource() != CustomerIdentity.ProvisioningSource.ADMINISTRATOR
                    || customer.getStatus() != CustomerIdentity.Status.PENDING_VERIFICATION) {
                throw new ResourceConflictException("demo customer is not pending administrator provisioning");
            }
            selected.add(customer);
        }

        Instant now = Instant.now();
        String actor = audit.currentActor();
        for (CustomerIdentity customer : selected) {
            challenges.findByTenantIdAndCustomerIdAndTypeAndUsedAtIsNull(tenantId, customer.getId(),
                    CustomerIdentityChallenge.Type.EMAIL_VERIFICATION).forEach(challenge -> challenge.invalidate(now));
            customer.verify(now);
            lifecycleAudit.record(tenantId, actor, "CUSTOMER_DEMO_ACTIVATED", "customer_identity",
                    customer.getId().toString(), Map.of("evidence", "SIMULATED_DEMO", "emailDomain", allowedDomain),
                    customer.getId().toString());
        }
        return ResponseEntity.ok(selected.stream().map(customer -> new CustomerResponse(customer.getId(),
                customer.getEmail(), customer.getDisplayName(), customer.getGivenName(), customer.getFamilyName(),
                customer.getStatus(), customer.getEmailVerifiedAt(), customer.getCreatedAt(), customer.getRevision(),
                customer.getProvisioningSource())).toList());
    }
}
