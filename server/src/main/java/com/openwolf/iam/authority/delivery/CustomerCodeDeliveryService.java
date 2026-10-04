package com.openwolf.iam.authority.delivery;

import com.openwolf.iam.entity.CustomerIdentity;
import com.openwolf.iam.repository.CustomerIdentityRepository;
import com.openwolf.iam.security.SecretProtector;
import com.openwolf.iam.service.CiamLifecycleAuditService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionTemplate;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Locale;
import java.util.Map;
import java.util.UUID;

/**
 * Phase 3.1 durable code delivery. A delivery row is written in the same transaction as its challenge; attempts run
 * outside any database transaction under a short lease, so a provider call never holds row locks and two workers never
 * attempt the same delivery at once. The code is decrypted only for the provider call and is erased from the row as
 * soon as the delivery is sent or abandoned. Nothing here logs or audits the code or the destination address.
 */
@Service
public class CustomerCodeDeliveryService {
    private static final Logger log = LoggerFactory.getLogger(CustomerCodeDeliveryService.class);
    private static final Duration LEASE = Duration.ofSeconds(60);

    private final CustomerCodeDeliveryRepository deliveries;
    private final CustomerIdentityRepository customers;
    private final ObjectProvider<CustomerCodeDeliveryProvider> providers;
    private final SecretProtector secrets;
    private final CiamLifecycleAuditService audit;
    private final JdbcTemplate jdbc;
    private final TransactionTemplate tx;
    private final Clock clock;
    private final int maxAttempts;
    private final Duration initialBackoff;
    private final boolean workerEnabled;

    @org.springframework.beans.factory.annotation.Autowired
    public CustomerCodeDeliveryService(CustomerCodeDeliveryRepository deliveries, CustomerIdentityRepository customers,
                                       ObjectProvider<CustomerCodeDeliveryProvider> providers, SecretProtector secrets,
                                       CiamLifecycleAuditService audit, JdbcTemplate jdbc,
                                       PlatformTransactionManager transactions,
                                       @Value("${iam.ciam.delivery.max-attempts:5}") int maxAttempts,
                                       @Value("${iam.ciam.delivery.initial-backoff:PT30S}") Duration initialBackoff,
                                       @Value("${iam.ciam.delivery.worker-enabled:true}") boolean workerEnabled) {
        this(deliveries, customers, providers, secrets, audit, jdbc, requiresNew(transactions),
                Clock.systemUTC(), maxAttempts, initialBackoff, workerEnabled);
    }

    CustomerCodeDeliveryService(CustomerCodeDeliveryRepository deliveries, CustomerIdentityRepository customers,
                                ObjectProvider<CustomerCodeDeliveryProvider> providers, SecretProtector secrets,
                                CiamLifecycleAuditService audit, JdbcTemplate jdbc, TransactionTemplate tx, Clock clock,
                                int maxAttempts, Duration initialBackoff, boolean workerEnabled) {
        if (maxAttempts < 1 || maxAttempts > 20 || initialBackoff.isNegative()) {
            throw new IllegalArgumentException("customer code delivery limits are invalid");
        }
        this.deliveries = deliveries; this.customers = customers; this.providers = providers; this.secrets = secrets;
        this.audit = audit; this.jdbc = jdbc; this.tx = tx; this.clock = clock; this.maxAttempts = maxAttempts;
        this.initialBackoff = initialBackoff; this.workerEnabled = workerEnabled;
    }

    /** Attempts may run from an after-commit callback, so they always use their own transactions. */
    private static TransactionTemplate requiresNew(PlatformTransactionManager transactions) {
        TransactionTemplate template = new TransactionTemplate(transactions);
        template.setPropagationBehavior(TransactionTemplate.PROPAGATION_REQUIRES_NEW);
        return template;
    }

    /** True only when a real provider adapter is configured. */
    public boolean available() {
        return providers.getIfAvailable() != null;
    }

    /**
     * Records a delivery for a freshly issued challenge, in the caller's transaction. Pending deliveries of earlier
     * challenges of the same purpose are abandoned (their codes were invalidated with the challenge).
     */
    @Transactional(propagation = Propagation.MANDATORY)
    public UUID enqueue(String tenantId, UUID customerId, UUID challengeId, CustomerCodeDeliveryProvider.Purpose purpose,
                        String destination, String code, Instant expiresAt) {
        Instant now = clock.instant();
        deliveries.abandonPending(tenantId, customerId, purpose.name(), now);
        CustomerCodeDelivery delivery = deliveries.save(new CustomerCodeDelivery(tenantId, customerId, challengeId,
                purpose, secrets.keyedDigest("customer-code-destination", destination.toLowerCase(Locale.ROOT)),
                secrets.protect(code), maxAttempts, expiresAt, now));
        audit.record(tenantId, "system", "CUSTOMER_CODE_DELIVERY_QUEUED", "customer_code_delivery",
                delivery.getId().toString(), Map.of("purpose", purpose.name(), "channel", "EMAIL",
                        "challengeId", challengeId.toString()), delivery.getId().toString());
        return delivery.getId();
    }

    /** Due deliveries, oldest first. Each is claimed individually, so concurrent workers never double-attempt. */
    public int runDue(int limit) {
        int attempted = 0;
        for (UUID id : deliveries.due(clock.instant(), limit)) {
            if (attempt(id)) attempted++;
        }
        return attempted;
    }

    @Scheduled(fixedDelayString = "${iam.ciam.delivery.worker-interval:PT15S}",
            initialDelayString = "${iam.ciam.delivery.worker-interval:PT15S}")
    public void scheduledRun() {
        if (!workerEnabled || !available()) return;
        try {
            runDue(50);
        } catch (RuntimeException failure) {
            log.warn("customer code delivery pass failed: {}", failure.getClass().getSimpleName());
        }
    }

    /** One attempt for one delivery; returns false when it was not due or another worker holds it. */
    public boolean attempt(UUID deliveryId) {
        Instant now = clock.instant();
        Claimed claimed = tx.execute(status -> claim(deliveryId, now));
        if (claimed == null) return false;
        if (claimed.abandonReason() != null) {
            finish(deliveryId, claimed, () -> deliveries.abandon(deliveryId, claimed.abandonReason(), clock.instant()),
                    "CUSTOMER_CODE_DELIVERY_ABANDONED", Map.of("reason", claimed.abandonReason()));
            return true;
        }
        CustomerCodeDeliveryProvider provider = providers.getIfAvailable();
        if (provider == null) {
            // Provider removed while deliveries were pending: retry later, never report success.
            tx.executeWithoutResult(status -> deliveries.markRetry(deliveryId, backoff(claimed.attempts()),
                    "provider_unavailable", null, clock.instant()));
            return true;
        }
        CustomerCodeDeliveryProvider.Receipt receipt;
        try {
            receipt = provider.deliver(new CustomerCodeDeliveryProvider.Message(deliveryId, claimed.tenantId(),
                    CustomerCodeDeliveryProvider.Channel.EMAIL, claimed.destination(), claimed.purpose(), claimed.code(),
                    claimed.expiresAt()));
        } catch (CustomerCodeDeliveryProvider.DeliveryFailed failed) {
            onFailure(deliveryId, claimed, provider.name(), failed.permanent() ? "permanent_failure" : "transient_failure",
                    failed.permanent());
            return true;
        } catch (RuntimeException failed) {
            onFailure(deliveryId, claimed, provider.name(), "provider_error", false);
            return true;
        }
        String reference = receipt == null || receipt.providerMessageRef() == null ? null
                : truncate(receipt.providerMessageRef());
        finish(deliveryId, claimed, () -> deliveries.markSent(deliveryId, provider.name(), reference, clock.instant()),
                "CUSTOMER_CODE_DELIVERY_SENT", reference == null ? Map.of("provider", provider.name())
                        : Map.of("provider", provider.name(), "providerMessageRef", reference));
        return true;
    }

    private void onFailure(UUID id, Claimed claimed, String provider, String failure, boolean permanent) {
        Instant now = clock.instant();
        Instant next = backoff(claimed.attempts());
        if (permanent || claimed.attempts() >= claimed.maxAttempts() || !next.isBefore(claimed.expiresAt())) {
            finish(id, claimed, () -> deliveries.abandon(id, failure, now), "CUSTOMER_CODE_DELIVERY_ABANDONED",
                    Map.of("reason", failure, "attempts", claimed.attempts(), "provider", provider));
            return;
        }
        tx.executeWithoutResult(status -> {
            deliveries.markRetry(id, next, failure, provider, now);
            audit.record(claimed.tenantId(), "system", "CUSTOMER_CODE_DELIVERY_RETRY_SCHEDULED", "customer_code_delivery",
                    id.toString(), Map.of("reason", failure, "attempts", claimed.attempts(),
                            "nextAttemptAt", next.toString()), id.toString());
        });
    }

    private void finish(UUID id, Claimed claimed, java.util.function.IntSupplier update, String event,
                        Map<String, ?> details) {
        tx.executeWithoutResult(status -> {
            if (update.getAsInt() == 1) {
                audit.record(claimed.tenantId(), "system", event, "customer_code_delivery", id.toString(), details,
                        id.toString());
            }
        });
    }

    private Claimed claim(UUID id, Instant now) {
        if (deliveries.claim(id, now, now.plus(LEASE)) != 1) return null;
        CustomerCodeDelivery d = deliveries.findById(id).orElseThrow();
        // Native update bypassed the persistence context; read the claimed values with a scalar query.
        Map<String, Object> row = jdbc.queryForMap("SELECT attempts, protected_code FROM customer_code_deliveries "
                + "WHERE id = ?", id);
        int attempts = ((Number) row.get("attempts")).intValue();
        CustomerIdentity customer = customers.findByTenantIdAndId(d.getTenantId(), d.getCustomerId()).orElse(null);
        String abandon = null;
        if (!now.isBefore(d.getExpiresAt())) abandon = "expired";
        else if (customer == null) abandon = "customer_missing";
        else if (!challengeOutstanding(d.getChallengeId(), now)) abandon = "challenge_no_longer_valid";
        else if (d.getPurpose() == CustomerCodeDeliveryProvider.Purpose.EMAIL_VERIFICATION
                && customer.getStatus() != CustomerIdentity.Status.PENDING_VERIFICATION) abandon = "already_verified";
        else if (d.getPurpose() == CustomerCodeDeliveryProvider.Purpose.PASSWORD_RECOVERY
                && customer.getStatus() != CustomerIdentity.Status.ACTIVE) abandon = "customer_not_active";
        String code = abandon == null ? secrets.reveal((String) row.get("protected_code")) : null;
        return new Claimed(d.getTenantId(), d.getPurpose(), customer == null ? null : customer.getEmail(), code,
                d.getExpiresAt(), attempts, d.getMaxAttempts(), abandon);
    }

    private boolean challengeOutstanding(UUID challengeId, Instant now) {
        Integer open = jdbc.queryForObject("SELECT count(*) FROM customer_identity_challenges WHERE id = ? "
                + "AND used_at IS NULL AND expires_at > ?", Integer.class, challengeId, java.sql.Timestamp.from(now));
        return open != null && open == 1;
    }

    private Instant backoff(int attempts) {
        long factor = 1L << Math.min(Math.max(attempts - 1, 0), 10);
        return clock.instant().plus(initialBackoff.multipliedBy(factor));
    }

    private static String truncate(String value) {
        return value.length() > 200 ? value.substring(0, 200) : value;
    }

    private record Claimed(String tenantId, CustomerCodeDeliveryProvider.Purpose purpose, String destination,
                           String code, Instant expiresAt, int attempts, int maxAttempts, String abandonReason) {
        @Override
        public String toString() { return "Claimed[tenantId=" + tenantId + ", purpose=" + purpose + "]"; }
    }
}
