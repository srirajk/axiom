package com.openwolf.iam.policystudio.lifecycle;

import com.openwolf.iam.tenancy.ActiveTenantDirectory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

/**
 * Makes the Studio's inherited manifest/base bundle explicit in the live policy-version pointer.
 *
 * <p>A freshly seeded demo tenant can legitimately have no tenant-authored child policy yet: its
 * current permissions are the immutable manifest/base ceiling. Consequence review signs a concrete
 * current bundle id, and promotion compare-and-sets from that exact id. Therefore the first Studio
 * review must not leave the active pointer as {@code null}; it should register the inherited base
 * snapshot as the tenant's current version and let the normal stale-review / CAS machinery continue to
 * enforce exact equality from there.
 */
@Service
public class StudioBaselineActivationService {

    private static final Logger log = LoggerFactory.getLogger(StudioBaselineActivationService.class);

    private final ActiveTenantDirectory directory;

    public StudioBaselineActivationService(ActiveTenantDirectory directory) {
        this.directory = directory;
    }

    /**
     * Ensure a tenant with no active policy version has an explicit baseline pointer.
     *
     * <p>If the tenant already has an active pointer, this method deliberately does not rewrite it. A
     * review computed against the wrong baseline will still fail closed at approval/promotion time.
     */
    public void ensureExplicitBaseline(String tenantId, String baselineBundleId) {
        if (tenantId == null || tenantId.isBlank()) {
            throw new IllegalArgumentException("tenantId must be set");
        }
        if (baselineBundleId == null || baselineBundleId.isBlank()) {
            throw new IllegalArgumentException("baselineBundleId must be set");
        }
        if (directory.find(tenantId).isPresent()) {
            return;
        }
        long version = directory.compareAndActivate(tenantId, null, baselineBundleId);
        log.info("Policy Studio registered inherited baseline '{}' for tenant '{}' (directory v{})",
                baselineBundleId, tenantId, version);
    }
}
