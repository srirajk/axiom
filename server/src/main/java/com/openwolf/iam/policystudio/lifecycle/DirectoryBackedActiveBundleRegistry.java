package com.openwolf.iam.policystudio.lifecycle;

import com.openwolf.iam.policystudio.TenantActiveBundleRegistry;
import com.openwolf.iam.tenancy.ActiveTenantDirectory;
import org.springframework.context.annotation.Primary;
import org.springframework.stereotype.Component;

/**
 * The single source of truth for a tenant's active policy bundle (Axiom Story C5), unifying C4's
 * staleness pointer with B4's live directory. C4 introduced {@code TenantActiveBundleRegistry} behind an
 * in-memory seam and explicitly deferred the durable, promotion-owned pointer to this story; C5 fulfils
 * it by reading B4's {@link ActiveTenantDirectory} — the exact pointer the promotion CAS advances — so
 * the approval staleness gate and the promotion machine never disagree about what is live.
 *
 * <p>Marked {@link Primary} so it wins over C4's in-memory placeholder wherever the container injects a
 * {@code TenantActiveBundleRegistry}; the placeholder stays available for hermetic C4 unit tests that
 * construct it directly.
 */
@Component
@Primary
public class DirectoryBackedActiveBundleRegistry implements TenantActiveBundleRegistry {

    private final ActiveTenantDirectory directory;

    public DirectoryBackedActiveBundleRegistry(ActiveTenantDirectory directory) {
        this.directory = directory;
    }

    @Override
    public String activeBundleId(String tenantId) {
        return directory.find(tenantId).orElse(null);
    }
}
