package com.openwolf.iam.policystudio;

/**
 * The full, deterministic context handed to the model for one authoring turn (Axiom Story C2) and
 * re-used verbatim by the post-generation gate. Bundling the vocabulary, author scope, and base
 * ceiling into one immutable request means the model prompt and the validator are grounded in the
 * <em>same</em> facts — the model cannot be graded against a looser contract than it was given.
 *
 * @param intent           the author's natural-language policy intent
 * @param vocabulary       the closed manifest vocabulary the policy may reference (C2.3)
 * @param authorScope      the author's own tenant scope — the subtree the artifact may not escape
 * @param subscopesEnabled whether the author is allowed to target a strict descendant of their
 *                         tenant (true) or only their exact tenant (false, the default posture)
 * @param baseCeiling      the immutable base ceiling the candidate must totally cover (C2.4)
 */
public record PolicyAuthoringRequest(
        String intent,
        ManifestVocabulary vocabulary,
        TenantScope authorScope,
        boolean subscopesEnabled,
        BaseCeiling baseCeiling) {

    public PolicyAuthoringRequest {
        if (intent == null || intent.isBlank()) {
            throw new IllegalArgumentException("intent must be set");
        }
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
