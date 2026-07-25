package com.openwolf.iam.policystudio.lifecycle;

import com.openwolf.iam.policystudio.BaseCeiling;
import com.openwolf.iam.policystudio.ManifestVocabulary;
import com.openwolf.iam.policystudio.TenantScope;

/**
 * The grounding facts {@link PolicyPromotionService} re-validates a candidate bundle against at
 * promotion time (Axiom H2). It carries the SAME three inputs the C2 authoring gate used — the closed
 * manifest {@link ManifestVocabulary}, the author's own {@link TenantScope}, and the immutable
 * {@link BaseCeiling} — so promotion can re-run {@link com.openwolf.iam.policystudio.GeneratedPolicyValidator}
 * on the candidate rather than trusting that it was validated once at authoring time.
 *
 * <p><b>Why a context (not a caller-supplied ceiling):</b> the promotion candidate is a
 * {@link PolicyBundle} (rendered Cerbos YAML + test metadata); it does NOT carry a typed vocabulary or
 * base ceiling, and the base ceiling cannot be reconstructed from the bundle's YAML alone (its
 * derived-role modules are not resource policies the studio parser will accept). So these facts are
 * supplied by a trusted {@link PromotionValidationContextProvider}, keyed off the bundle and the exact
 * parsed tenant child resource kind — never taken from the promotion request. This closes both the
 * "promote() trusts a caller-supplied ceiling" hole and the multi-resource "first child chooses every
 * ceiling" hole.
 *
 * @param vocabulary       the closed manifest vocabulary the candidate may reference
 * @param authorScope      the tenant subtree the candidate's policies may not escape
 * @param subscopesEnabled whether a strict descendant scope is allowed (default posture: false)
 * @param baseCeiling      the immutable base ceiling the candidate must totally cover
 */
public record PromotionValidationContext(
        ManifestVocabulary vocabulary,
        TenantScope authorScope,
        boolean subscopesEnabled,
        BaseCeiling baseCeiling) {

    public PromotionValidationContext {
        if (vocabulary == null || authorScope == null || baseCeiling == null) {
            throw new IllegalArgumentException("vocabulary, authorScope and baseCeiling must be set");
        }
        if (!vocabulary.resourceKind().equals(baseCeiling.resourceKind())) {
            throw new IllegalArgumentException(
                    "vocabulary resourceKind '" + vocabulary.resourceKind()
                            + "' != base ceiling resourceKind '" + baseCeiling.resourceKind() + "'");
        }
    }
}
