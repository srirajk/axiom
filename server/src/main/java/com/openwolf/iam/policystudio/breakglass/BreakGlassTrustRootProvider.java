package com.openwolf.iam.policystudio.breakglass;

import com.openwolf.iam.policystudio.BaseCeiling;
import com.openwolf.iam.policystudio.ManifestVocabulary;

/**
 * Resolves the security boundaries for break-glass authoring from trusted server state.
 *
 * <p>The HTTP caller is deliberately not allowed to supply any of these values. Implementations must
 * fail closed when a tenant/resource has no explicitly configured emergency surface.
 */
public interface BreakGlassTrustRootProvider {

    TrustRoots resolve(String tenantId, String resourceKind);

    record TrustRoots(ManifestVocabulary vocabulary,
                      BaseCeiling baseCeiling,
                      BreakGlassAllowlist allowlist) {
    }
}
