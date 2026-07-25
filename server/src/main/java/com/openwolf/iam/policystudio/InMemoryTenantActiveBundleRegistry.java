package com.openwolf.iam.policystudio;

import org.springframework.stereotype.Component;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * A simple in-memory {@link TenantActiveBundleRegistry} (Axiom Story C4). It models the tenant→active
 * bundle pointer the staleness gate reads. The durable, promotion-owned implementation is out of scope
 * for C4 (it belongs to the promotion/lifecycle story, C5); this is the seam behind the port so the
 * approval gate and its harness are exercised end-to-end.
 */
@Component
public class InMemoryTenantActiveBundleRegistry implements TenantActiveBundleRegistry {

    private final Map<String, String> active = new ConcurrentHashMap<>();

    @Override
    public String activeBundleId(String tenantId) {
        return active.get(tenantId);
    }

    /** Set (or advance) the tenant's active bundle pointer — used by tests and the promotion path. */
    public void setActiveBundle(String tenantId, String bundleId) {
        active.put(tenantId, bundleId);
    }
}
