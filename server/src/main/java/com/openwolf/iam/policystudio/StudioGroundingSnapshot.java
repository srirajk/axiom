package com.openwolf.iam.policystudio;

import java.util.List;

/**
 * Server-side studio grounding for one tenant/resource kind. The values are assembled from the
 * manifest/typed source and then reused by draft, review, and promotion validation.
 */
public record StudioGroundingSnapshot(
        String tenantId,
        ManifestVocabulary vocabulary,
        BaseCeiling baseCeiling,
        ConsequenceFixtureMatrix matrix,
        BundleSnapshot current,
        List<String> manifestRefs) {
}
