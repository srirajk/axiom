package com.openwolf.iam.authority.delivery;

import java.time.Instant;
import java.util.UUID;

/**
 * Phase 3.1 adapter to a real message provider (e-mail today). No implementation ships with Axiom: the provider, its
 * sender identity and its data-processing terms are a deployment decision. Without a provider bean, customer flows
 * that need a code are refused rather than reported as delivered.
 *
 * <p>Implementations must treat {@link Message#deliveryId()} as an idempotency key: Axiom retries after failures and
 * after crashes between a provider call and recording its result, so the same delivery may be offered more than once.
 * Implementations must never log {@link Message#code()}.
 */
public interface CustomerCodeDeliveryProvider {

    enum Channel { EMAIL }

    enum Purpose { EMAIL_VERIFICATION, PASSWORD_RECOVERY }

    record Message(UUID deliveryId, String tenantId, Channel channel, String destination, Purpose purpose,
                   String code, Instant expiresAt) {
        @Override
        public String toString() {
            return "Message[deliveryId=" + deliveryId + ", tenantId=" + tenantId + ", channel=" + channel
                    + ", purpose=" + purpose + ", expiresAt=" + expiresAt + "]";
        }
    }

    /** Provider acceptance: a non-secret reference for audit and support. Acceptance is not proof of receipt. */
    record Receipt(String providerMessageRef) {}

    /** Delivery failed; {@code permanent} failures (e.g. rejected destination) are not retried. */
    final class DeliveryFailed extends RuntimeException {
        private final boolean permanent;

        public DeliveryFailed(String reason, boolean permanent) {
            super(reason, null, false, false);
            this.permanent = permanent;
        }

        public boolean permanent() { return permanent; }
    }

    /** Stable, non-secret provider name recorded with each delivery. */
    String name();

    Receipt deliver(Message message);
}
