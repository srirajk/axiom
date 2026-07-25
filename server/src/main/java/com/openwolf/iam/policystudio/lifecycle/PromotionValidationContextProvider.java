package com.openwolf.iam.policystudio.lifecycle;

/**
 * Supplies the {@link PromotionValidationContext} (manifest vocabulary + author scope + immutable base
 * ceiling) a candidate bundle must be re-validated against at promotion time (Axiom H2). It is a trusted
 * server-side source, keyed off the candidate and each parsed tenant child — promotion never accepts
 * these facts from the request. A tenant-wide bundle can contain multiple resource kinds, and each kind
 * must be checked against its own vocabulary and immutable ceiling.
 *
 * <p>Behind a port so the deterministic harness can drive the re-validation with fixture vocabulary /
 * ceilings, while production derives them from the effective per-tenant manifest.
 */
public interface PromotionValidationContextProvider {

    /**
     * @param candidate    the immutable tenant-wide candidate bundle
     * @param resourceKind the parsed tenant child's resource kind
     * @param childScope   the parsed tenant child's scope
     * @return the grounding context to re-validate that exact child against.
     * @throws IllegalStateException if no trusted context can be produced — promotion must FAIL CLOSED
     *                               rather than validate a candidate against an empty/absent ceiling.
     */
    PromotionValidationContext contextFor(PolicyBundle candidate, String resourceKind, String childScope);
}
