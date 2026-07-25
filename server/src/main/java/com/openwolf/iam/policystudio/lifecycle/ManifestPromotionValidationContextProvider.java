package com.openwolf.iam.policystudio.lifecycle;

import com.openwolf.iam.policystudio.StudioGroundingProvider;
import com.openwolf.iam.policystudio.StudioGroundingSnapshot;
import com.openwolf.iam.policystudio.TenantScope;
import org.springframework.stereotype.Component;

/**
 * The production {@link PromotionValidationContextProvider} (Axiom H2). It derives the validator context
 * from the same manifest-backed source used by the author/review APIs. The base ceiling is never rebuilt
 * from rendered bundle YAML. {@link PolicyPromotionService} parses every tenant child and asks for an
 * independent context keyed by that child's resource kind, so one tenant-wide bundle cannot validate all
 * children against whichever resource happened to sort first.
 */
@Component
public class ManifestPromotionValidationContextProvider implements PromotionValidationContextProvider {

    private final StudioGroundingProvider grounding;

    public ManifestPromotionValidationContextProvider(StudioGroundingProvider grounding) {
        this.grounding = grounding;
    }

    @Override
    public PromotionValidationContext contextFor(
            PolicyBundle candidate, String resourceKind, String childScope) {
        if (candidate == null) {
            throw new IllegalArgumentException("candidate bundle must be set");
        }
        if (resourceKind == null || resourceKind.isBlank()) {
            throw new IllegalArgumentException("resourceKind must be set");
        }
        if (childScope == null || childScope.isBlank()) {
            throw new IllegalArgumentException("childScope must be set");
        }
        StudioGroundingSnapshot snapshot = grounding.snapshot(candidate.tenantId(), resourceKind);
        boolean subscopesEnabled = !candidate.tenantId().equals(childScope);
        return new PromotionValidationContext(
                snapshot.vocabulary(),
                TenantScope.of(candidate.tenantId()),
                subscopesEnabled,
                snapshot.baseCeiling());
    }
}
