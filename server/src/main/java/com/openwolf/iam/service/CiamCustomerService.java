package com.openwolf.iam.service;

import com.openwolf.iam.dto.CiamContracts.ChallengeAction;
import com.openwolf.iam.dto.CiamContracts.CustomerResponse;
import com.openwolf.iam.dto.CiamContracts.RecoveryChallengeResponse;
import com.openwolf.iam.dto.CiamContracts.RegistrationResponse;
import com.openwolf.iam.entity.CustomerIdentity;
import com.openwolf.iam.entity.CustomerIdentityChallenge;
import com.openwolf.iam.exception.EntityNotFoundException;
import com.openwolf.iam.exception.ResourceConflictException;
import com.openwolf.iam.repository.CustomerIdentityChallengeRepository;
import com.openwolf.iam.repository.CustomerIdentityRepository;
import com.openwolf.iam.repository.CustomerDelegationGrantRepository;
import com.openwolf.iam.repository.TenantRepository;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.HexFormat;
import java.util.Locale;
import java.util.Map;
import java.util.UUID;
import java.util.List;

@Service
@Transactional
public class CiamCustomerService {
    private final CustomerIdentityRepository customers;
    private final CustomerIdentityChallengeRepository challenges;
    private final TenantRepository tenants;
    private final CustomerDelegationGrantRepository delegationGrants;
    private final IamSessionService sessions;
    private final PasswordEncoder passwordEncoder;
    private final CiamLifecycleAuditService audit;
    private final SecureRandom random = new SecureRandom();
    private final Clock clock;
    private final Duration challengeTtl;
    private final boolean discloseLocalDemoChallenges;

    @org.springframework.beans.factory.annotation.Autowired
    public CiamCustomerService(CustomerIdentityRepository customers,
                               CustomerIdentityChallengeRepository challenges,
                               TenantRepository tenants, CustomerDelegationGrantRepository delegationGrants,
                               IamSessionService sessions, PasswordEncoder passwordEncoder,
                               CiamLifecycleAuditService audit,
                               @Value("${iam.ciam.challenge-ttl-seconds:900}") long challengeTtlSeconds,
                               @Value("${iam.ciam.local-demo-challenge-disclosure:false}") boolean disclose) {
        this(customers, challenges, tenants, delegationGrants, sessions, passwordEncoder, audit,
                Clock.systemUTC(), Duration.ofSeconds(challengeTtlSeconds), disclose);
    }

    CiamCustomerService(CustomerIdentityRepository customers,
                        CustomerIdentityChallengeRepository challenges,
                        TenantRepository tenants, CustomerDelegationGrantRepository delegationGrants,
                        IamSessionService sessions, PasswordEncoder passwordEncoder,
                        CiamLifecycleAuditService audit, Clock clock, Duration challengeTtl,
                        boolean discloseLocalDemoChallenges) {
        if (challengeTtl.isNegative() || challengeTtl.isZero() || challengeTtl.compareTo(Duration.ofHours(1)) > 0) {
            throw new IllegalArgumentException("CIAM challenge TTL must be between 1 second and 1 hour");
        }
        this.customers = customers;
        this.challenges = challenges;
        this.tenants = tenants;
        this.delegationGrants = delegationGrants;
        this.sessions = sessions;
        this.passwordEncoder = passwordEncoder;
        this.audit = audit;
        this.clock = clock;
        this.challengeTtl = challengeTtl;
        this.discloseLocalDemoChallenges = discloseLocalDemoChallenges;
    }

    public RegistrationResponse register(String tenantId, String email, String displayName,
                                         String password, String correlationId) {
        requireTenant(tenantId);
        String normalizedEmail = normalizeEmail(email);
        if (customers.findByTenantIdAndEmailIgnoreCase(tenantId, normalizedEmail).isPresent()) {
            throw new ResourceConflictException("customer identity already exists");
        }
        Instant now = clock.instant();
        CustomerIdentity customer = customers.save(new CustomerIdentity(tenantId, normalizedEmail,
                displayName.trim(), passwordEncoder.encode(password), now));
        ChallengeAction action = issue(customer, CustomerIdentityChallenge.Type.EMAIL_VERIFICATION, now);
        audit.record(tenantId, customer.getId().toString(), "CUSTOMER_REGISTERED", "customer_identity",
                customer.getId().toString(), Map.of("status", customer.getStatus().name()), correlationId);
        return new RegistrationResponse(toResponse(customer), disclosed(action));
    }

    public CustomerResponse verify(String tenantId, String token, String correlationId) {
        Instant now = clock.instant();
        CustomerIdentityChallenge challenge = findChallenge(tenantId,
                CustomerIdentityChallenge.Type.EMAIL_VERIFICATION, token);
        CustomerIdentity customer = requireCustomer(tenantId, challenge.getCustomerId());
        challenge.consume(now);
        customer.verify(now);
        audit.record(tenantId, customer.getId().toString(), "CUSTOMER_VERIFIED", "customer_identity",
                customer.getId().toString(), Map.of("status", customer.getStatus().name()), correlationId);
        return toResponse(customer);
    }

    public RecoveryChallengeResponse requestRecovery(String tenantId, String email, String correlationId) {
        requireTenant(tenantId);
        Instant now = clock.instant();
        CustomerIdentity customer = customers.findByTenantIdAndEmailIgnoreCase(tenantId, normalizeEmail(email))
                .filter(value -> value.getStatus() == CustomerIdentity.Status.ACTIVE).orElse(null);
        ChallengeAction action;
        if (customer == null) {
            action = localDemoAction("recovery", randomToken(), now.plus(challengeTtl));
        } else {
            action = issue(customer, CustomerIdentityChallenge.Type.PASSWORD_RECOVERY, now);
            audit.record(tenantId, customer.getId().toString(), "CUSTOMER_RECOVERY_CHALLENGE_ISSUED",
                    "customer_identity", customer.getId().toString(), Map.of("delivery", "LOCAL_DEMO"),
                    correlationId);
        }
        return new RecoveryChallengeResponse(true, disclosed(action));
    }

    public CustomerResponse recover(String tenantId, String token, String newPassword, String correlationId) {
        Instant now = clock.instant();
        CustomerIdentityChallenge challenge = findChallenge(tenantId,
                CustomerIdentityChallenge.Type.PASSWORD_RECOVERY, token);
        CustomerIdentity customer = requireCustomer(tenantId, challenge.getCustomerId());
        challenge.consume(now);
        customer.recoverCredential(passwordEncoder.encode(newPassword), now);
        int revokedSessions = sessions.revokeAllForPrincipal(tenantId, customer.getId().toString());
        int revokedGrants = revokeActiveGrants(tenantId, customer.getId(), "customer credential recovery", now,
                customer.getId().toString(), correlationId);
        audit.record(tenantId, customer.getId().toString(), "CUSTOMER_CREDENTIAL_RECOVERED",
                "customer_identity", customer.getId().toString(), Map.of("revokedSessions", revokedSessions,
                        "revokedDelegationGrants", revokedGrants, "tokenVersion", customer.getTokenVersion()), correlationId);
        return toResponse(customer);
    }

    @Transactional(readOnly = true)
    public CustomerResponse get(String tenantId, UUID customerId) {
        return toResponse(requireCustomer(tenantId, customerId));
    }

    @Transactional(readOnly = true)
    public List<CustomerResponse> list(String tenantId) {
        return customers.findByTenantIdOrderByCreatedAtAsc(tenantId).stream()
                .map(CiamCustomerService::toResponse).toList();
    }

    public CustomerResponse suspend(String tenantId, UUID customerId, String actorId, String correlationId) {
        CustomerIdentity customer = requireCustomer(tenantId, customerId);
        Instant now = clock.instant();
        customer.suspend(now);
        int revokedSessions = sessions.revokeAllForPrincipal(tenantId, customerId.toString());
        int revokedGrants = revokeActiveGrants(tenantId, customerId, "customer suspended", now, actorId,
                correlationId);
        audit.record(tenantId, actorId, "CUSTOMER_SUSPENDED", "customer_identity",
                customerId.toString(), Map.of("status", customer.getStatus().name(),
                        "revokedSessions", revokedSessions, "revokedDelegationGrants", revokedGrants), correlationId);
        return toResponse(customer);
    }

    public CustomerResponse reactivate(String tenantId, UUID customerId, String actorId, String correlationId) {
        CustomerIdentity customer = requireCustomer(tenantId, customerId);
        customer.reactivate(clock.instant());
        audit.record(tenantId, actorId, "CUSTOMER_REACTIVATED", "customer_identity",
                customerId.toString(), Map.of("status", customer.getStatus().name()), correlationId);
        return toResponse(customer);
    }

    CustomerIdentity requireCustomer(String tenantId, UUID customerId) {
        return customers.findByTenantIdAndId(tenantId, customerId)
                .orElseThrow(() -> new EntityNotFoundException("customer identity not found"));
    }

    private ChallengeAction issue(CustomerIdentity customer, CustomerIdentityChallenge.Type type, Instant now) {
        challenges.findByTenantIdAndCustomerIdAndTypeAndUsedAtIsNull(
                customer.getTenantId(), customer.getId(), type).forEach(value -> value.invalidate(now));
        String token = randomToken();
        Instant expiresAt = now.plus(challengeTtl);
        challenges.save(new CustomerIdentityChallenge(customer.getTenantId(), customer.getId(), type,
                hash(token), expiresAt, now));
        return localDemoAction(type == CustomerIdentityChallenge.Type.EMAIL_VERIFICATION
                ? "verification" : "recovery", token, expiresAt);
    }

    private CustomerIdentityChallenge findChallenge(String tenantId, CustomerIdentityChallenge.Type type,
                                                    String token) {
        return challenges.findByTenantIdAndTypeAndTokenHashAndUsedAtIsNull(tenantId, type, hash(token))
                .orElseThrow(() -> new ResourceConflictException("challenge is invalid or expired"));
    }

    private void requireTenant(String tenantId) {
        if (!tenants.existsById(tenantId)) throw new EntityNotFoundException("tenant not found");
    }

    private String randomToken() {
        byte[] value = new byte[32];
        random.nextBytes(value);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(value);
    }

    private static String hash(String token) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
                    .digest(token.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException ex) {
            throw new IllegalStateException("SHA-256 unavailable", ex);
        }
    }

    private static String normalizeEmail(String email) { return email.trim().toLowerCase(Locale.ROOT); }

    private static ChallengeAction localDemoAction(String kind, String token, Instant expiresAt) {
        return new ChallengeAction(kind, token, expiresAt, "LOCAL_DEMO");
    }

    private ChallengeAction disclosed(ChallengeAction action) {
        return discloseLocalDemoChallenges ? action : null;
    }

    private int revokeActiveGrants(String tenantId, UUID customerId, String reason, Instant now,
                                   String actorId, String correlationId) {
        var active = delegationGrants.findByTenantIdAndCustomerIdAndStatus(
                tenantId, customerId, com.openwolf.iam.entity.CustomerDelegationGrant.Status.ACTIVE);
        active.forEach(grant -> {
            grant.revoke(reason, now);
            audit.record(tenantId, actorId, "DELEGATION_GRANT_REVOKED", "delegation_grant",
                    grant.getId().toString(), Map.of("reason", reason), correlationId);
        });
        return active.size();
    }

    static CustomerResponse toResponse(CustomerIdentity value) {
        return new CustomerResponse(value.getId(), value.getEmail(), value.getDisplayName(), value.getStatus(),
                value.getEmailVerifiedAt(), value.getCreatedAt(), value.getRevision());
    }
}
