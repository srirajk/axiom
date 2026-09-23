package com.openwolf.iam.service;

import com.openwolf.iam.entity.CustomerIdentity;
import com.openwolf.iam.repository.CustomerIdentityRepository;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Locale;
import java.util.UUID;

@Service
@Transactional(readOnly = true)
public class CiamCustomerAuthenticationService {
    public record AuthenticatedCustomer(UUID customerId, String tenantId, String email,
                                        String displayName, String identityKind, long tokenVersion) {}

    private final CustomerIdentityRepository customers;
    private final PasswordEncoder passwordEncoder;

    public CiamCustomerAuthenticationService(CustomerIdentityRepository customers,
                                             PasswordEncoder passwordEncoder) {
        this.customers = customers;
        this.passwordEncoder = passwordEncoder;
    }

    public AuthenticatedCustomer authenticate(String tenantId, String email, String password) {
        CustomerIdentity customer = customers.findByTenantIdAndEmailIgnoreCase(
                        tenantId, email.trim().toLowerCase(Locale.ROOT))
                .filter(value -> value.getStatus() == CustomerIdentity.Status.ACTIVE)
                .orElseThrow(() -> new BadCredentialsException("customer authentication failed"));
        if (!passwordEncoder.matches(password, customer.getPasswordHash())) {
            throw new BadCredentialsException("customer authentication failed");
        }
        return new AuthenticatedCustomer(customer.getId(), tenantId, customer.getEmail(),
                customer.getDisplayName(), "customer", customer.getTokenVersion());
    }

    /** Token-time fail-closed check for subject-token and customer API validators. */
    public boolean isCurrentActive(String tenantId, UUID customerId, long tokenVersion) {
        return customers.findByTenantIdAndId(tenantId, customerId)
                .filter(value -> value.getStatus() == CustomerIdentity.Status.ACTIVE)
                .filter(value -> value.getTokenVersion() == tokenVersion)
                .isPresent();
    }
}
