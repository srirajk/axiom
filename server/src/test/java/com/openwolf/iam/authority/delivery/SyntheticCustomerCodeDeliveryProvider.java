package com.openwolf.iam.authority.delivery;

import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;

import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Test-only stand-in for a real message provider (Phase 3.1). It records what a real provider would have sent in an
 * in-memory inbox keyed by destination, can be told to fail, and is idempotent per delivery id. It is never a
 * production provider: Axiom ships none.
 */
public final class SyntheticCustomerCodeDeliveryProvider implements CustomerCodeDeliveryProvider {
    public record Delivered(UUID deliveryId, Purpose purpose, String code) {}

    public static final Map<String, List<Delivered>> INBOX = new ConcurrentHashMap<>();
    public static final AtomicInteger TRANSIENT_FAILURES = new AtomicInteger();
    public static final AtomicInteger PERMANENT_FAILURES = new AtomicInteger();
    public static final AtomicInteger CALLS = new AtomicInteger();
    private static final Map<UUID, Boolean> SEEN = new ConcurrentHashMap<>();

    @Override
    public String name() { return "synthetic-test-provider"; }

    @Override
    public Receipt deliver(Message message) {
        CALLS.incrementAndGet();
        if (PERMANENT_FAILURES.getAndUpdate(n -> Math.max(0, n - 1)) > 0) {
            throw new DeliveryFailed("destination rejected", true);
        }
        if (TRANSIENT_FAILURES.getAndUpdate(n -> Math.max(0, n - 1)) > 0) {
            throw new DeliveryFailed("provider temporarily unavailable", false);
        }
        if (SEEN.putIfAbsent(message.deliveryId(), Boolean.TRUE) == null) {
            INBOX.computeIfAbsent(message.destination(), k -> new CopyOnWriteArrayList<>())
                    .add(new Delivered(message.deliveryId(), message.purpose(), message.code()));
        }
        return new Receipt("synthetic-" + message.deliveryId());
    }

    /** Latest code delivered to an address for a purpose, or null. */
    public static String latest(String destination, Purpose purpose) {
        List<Delivered> delivered = INBOX.getOrDefault(destination, List.of());
        for (int i = delivered.size() - 1; i >= 0; i--) {
            if (delivered.get(i).purpose() == purpose) return delivered.get(i).code();
        }
        return null;
    }

    public static void reset() {
        TRANSIENT_FAILURES.set(0);
        PERMANENT_FAILURES.set(0);
    }

    @TestConfiguration
    public static class Config {
        @Bean
        CustomerCodeDeliveryProvider syntheticCustomerCodeDeliveryProvider() {
            return new SyntheticCustomerCodeDeliveryProvider();
        }
    }
}
