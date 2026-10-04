package com.openwolf.iam.service;

import com.openwolf.iam.authority.delivery.CustomerCodeDeliveryProvider;
import com.openwolf.iam.authority.delivery.CustomerCodeDeliveryService;
import com.openwolf.iam.dto.CiamContracts.ChallengeAction;
import com.openwolf.iam.dto.CiamContracts.CustomerResponse;
import com.openwolf.iam.dto.CiamContracts.RecoveryChallengeResponse;
import com.openwolf.iam.dto.CiamContracts.RegistrationResponse;
import com.openwolf.iam.entity.CustomerIdentity;
import com.openwolf.iam.entity.CustomerIdentityChallenge;
import com.openwolf.iam.exception.EntityNotFoundException;
import com.openwolf.iam.exception.ResourceConflictException;
import com.openwolf.iam.exception.ServiceUnavailableException;
import com.openwolf.iam.repository.CustomerIdentityChallengeRepository;
import com.openwolf.iam.repository.CustomerIdentityRepository;
import com.openwolf.iam.repository.CustomerDelegationGrantRepository;
import com.openwolf.iam.repository.TenantRepository;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionSynchronization;
import org.springframework.transaction.support.TransactionSynchronizationManager;

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
    private CustomerCodeDeliveryService delivery;
    private int maxChallengesPerHour = 5;

    @org.springframework.beans.factory.annotation.Autowired
    public CiamCustomerService(CustomerIdentityRepository customers,
                               CustomerIdentityChallengeRepository challenges,
                               TenantRepository tenants, CustomerDelegationGrantRepository delegationGrants,
                               IamSessionService sessions, PasswordEncoder passwordEncoder,
                               CiamLifecycleAuditService audit,
                               @Value("${iam.ciam.challenge-ttl-seconds:900}") long challengeTtlSeconds,
                               @Value("${iam.ciam.local-demo-challenge-disclosure:false}") boolean disclose,
                               CustomerCodeDeliveryService delivery,
                               @Value("${iam.ciam.max-challenges-per-hour:5}") int maxChallengesPerHour) {
        this(customers, challenges, tenants, delegationGrants, sessions, passwordEncoder, audit,
                Clock.systemUTC(), Duration.ofSeconds(challengeTtlSeconds), disclose);
        if (maxChallengesPerHour < 1) throw new IllegalArgumentException("challenge issuance limit must be positive");
        this.delivery = delivery;
        this.maxChallengesPerHour = maxChallengesPerHour;
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
        requireCodeChannel();
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
        return new RegistrationResponse(toResponse(customer), disclosed(action), deliveryState());
    }

    /**
     * Administrator provisioning. The identity is created pending verification and cannot authenticate until the
     * customer completes the ordinary verification challenge (requested by the customer, delivered to the customer).
     * No challenge or code is issued to, or disclosed to, the administrator.
     */
    public CustomerResponse provision(String tenantId, String email, String displayName, String initialPassword,
                                      String actorId, String correlationId) {
        requireTenant(tenantId);
        String normalizedEmail = normalizeEmail(email);
        if (customers.findByTenantIdAndEmailIgnoreCase(tenantId, normalizedEmail).isPresent()) {
            throw new ResourceConflictException("customer identity already exists");
        }
        CustomerIdentity customer = customers.save(CustomerIdentity.provisionedByAdministrator(tenantId,
                normalizedEmail, displayName.trim(), passwordEncoder.encode(initialPassword), clock.instant()));
        audit.record(tenantId, actorId, "CUSTOMER_PROVISIONED", "customer_identity", customer.getId().toString(),
                Map.of("status", customer.getStatus().name(), "provisioningSource",
                        customer.getProvisioningSource().name()), correlationId);
        return toResponse(customer);
    }

    /**
     * Phase 3.1 resend of an e-mail verification code. The response never reveals whether the address exists or is
     * pending, and issuance is bounded per customer per hour.
     */
    public RecoveryChallengeResponse requestVerification(String tenantId, String email, String correlationId) {
        requireTenant(tenantId);
        requireCodeChannel();
        Instant now = clock.instant();
        CustomerIdentity customer = customers.findByTenantIdAndEmailIgnoreCase(tenantId, normalizeEmail(email))
                .filter(value -> value.getStatus() == CustomerIdentity.Status.PENDING_VERIFICATION).orElse(null);
        ChallengeAction action = null;
        if (customer != null && withinIssuanceLimit(customer, CustomerIdentityChallenge.Type.EMAIL_VERIFICATION, now)) {
            action = issue(customer, CustomerIdentityChallenge.Type.EMAIL_VERIFICATION, now);
            audit.record(tenantId, customer.getId().toString(), "CUSTOMER_VERIFICATION_CHALLENGE_ISSUED",
                    "customer_identity", customer.getId().toString(), Map.of("delivery", deliveryState()), correlationId);
        }
        return new RecoveryChallengeResponse(true, disclosed(action), deliveryState());
    }

    public CustomerResponse verify(String tenantId, String token, String correlationId) {
        Instant now = clock.instant();
        CustomerIdentityChallenge challenge = findChallenge(tenantId,
                CustomerIdentityChallenge.Type.EMAIL_VERIFICATION, token);
        CustomerIdentity customer = requireCustomer(tenantId, challenge.getCustomerId());
        consume(challenge, now);
        customer.verify(now);
        audit.record(tenantId, customer.getId().toString(), "CUSTOMER_VERIFIED", "customer_identity",
                customer.getId().toString(), Map.of("status", customer.getStatus().name()), correlationId);
        return toResponse(customer);
    }

    public RecoveryChallengeResponse requestRecovery(String tenantId, String email, String correlationId) {
        requireTenant(tenantId);
        // Recovery needs a real delivery provider: a recovery code is never disclosed, not even by the local-demo aid
        // (anyone able to reach the endpoint could take over any account). Refused identically for every address.
        if (!providerDelivery()) throw new ServiceUnavailableException("customer code delivery is not configured");
        Instant now = clock.instant();
        CustomerIdentity customer = customers.findByTenantIdAndEmailIgnoreCase(tenantId, normalizeEmail(email))
                .filter(value -> value.getStatus() == CustomerIdentity.Status.ACTIVE).orElse(null);
        ChallengeAction action;
        if (customer == null || !withinIssuanceLimit(customer, CustomerIdentityChallenge.Type.PASSWORD_RECOVERY, now)) {
            action = null;
        } else {
            action = issue(customer, CustomerIdentityChallenge.Type.PASSWORD_RECOVERY, now);
            audit.record(tenantId, customer.getId().toString(), "CUSTOMER_RECOVERY_CHALLENGE_ISSUED",
                    "customer_identity", customer.getId().toString(), Map.of("delivery", deliveryState()),
                    correlationId);
        }
        return new RecoveryChallengeResponse(true, null, deliveryState());
    }

    public CustomerResponse recover(String tenantId, String token, String newPassword, String correlationId) {
        Instant now = clock.instant();
        CustomerIdentityChallenge challenge = findChallenge(tenantId,
                CustomerIdentityChallenge.Type.PASSWORD_RECOVERY, token);
        CustomerIdentity customer = requireCustomer(tenantId, challenge.getCustomerId());
        consume(challenge, now);
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
        CustomerIdentityChallenge challenge = challenges.save(new CustomerIdentityChallenge(customer.getTenantId(),
                customer.getId(), type, hash(token), expiresAt, now));
        if (providerDelivery()) {
            UUID deliveryId = delivery.enqueue(customer.getTenantId(), customer.getId(), challenge.getId(),
                    type == CustomerIdentityChallenge.Type.EMAIL_VERIFICATION
                            ? CustomerCodeDeliveryProvider.Purpose.EMAIL_VERIFICATION
                            : CustomerCodeDeliveryProvider.Purpose.PASSWORD_RECOVERY,
                    customer.getEmail(), token, expiresAt);
            attemptAfterCommit(deliveryId);
        }
        return localDemoAction(type == CustomerIdentityChallenge.Type.EMAIL_VERIFICATION
                ? "verification" : "recovery", token, expiresAt);
    }

    /** True when a real provider delivers codes; the local-demo disclosure is then never used. */
    private boolean providerDelivery() {
        return delivery != null && delivery.available();
    }

    /** Code-dependent customer flows need a provider or the explicit local-demo disclosure; otherwise refuse. */
    private void requireCodeChannel() {
        if (!providerDelivery() && !discloseLocalDemoChallenges) {
            throw new ServiceUnavailableException("customer code delivery is not configured");
        }
    }

    /** What the caller may be told: queued for provider delivery, or a local-demo disclosure. Never "delivered". */
    private String deliveryState() {
        return providerDelivery() ? "QUEUED" : "LOCAL_DEMO";
    }

    private boolean withinIssuanceLimit(CustomerIdentity customer, CustomerIdentityChallenge.Type type, Instant now) {
        return challenges.countIssuedSince(customer.getTenantId(), customer.getId(), type.name(),
                now.minus(Duration.ofHours(1))) < maxChallengesPerHour;
    }

    /** First provider attempt right after the challenge commits; failures stay queued for the retry worker. */
    private void attemptAfterCommit(UUID deliveryId) {
        if (!TransactionSynchronizationManager.isSynchronizationActive()) return;
        TransactionSynchronizationManager.registerSynchronization(new TransactionSynchronization() {
            @Override
            public void afterCommit() {
                try {
                    delivery.attempt(deliveryId);
                } catch (RuntimeException deferred) {
                    // The delivery row is durable; the worker retries it. Nothing about the code is logged.
                }
            }
        });
    }

    private void consume(CustomerIdentityChallenge challenge, Instant now) {
        if (challenges.consume(challenge.getId(), now) != 1) {
            throw new ResourceConflictException("challenge is invalid or expired");
        }
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
        return action != null && discloseLocalDemoChallenges && !providerDelivery() ? action : null;
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
                value.getEmailVerifiedAt(), value.getCreatedAt(), value.getRevision(), value.getProvisioningSource());
    }
}
