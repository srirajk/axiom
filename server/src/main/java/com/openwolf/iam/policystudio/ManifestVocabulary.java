package com.openwolf.iam.policystudio;

import java.util.Set;

/**
 * The closed vocabulary a generated policy is allowed to reference, derived from the tenant's
 * manifests + base-ceiling schema (Axiom Story C2.3). This is the grounding contract: the
 * validator rejects any rule that names a resource kind, action, role, data-classification, or
 * attribute that is not in these sets.
 *
 * <p>World B: none of these values are hardcoded domain literals in Java — they are supplied by a
 * {@code ManifestVocabularyProvider} that reads them from the effective manifest / base ceiling.
 * The tests feed fixtures directly; production wiring supplies the same shape from config.
 *
 * @param resourceKind    the single Cerbos resource kind this policy targets
 * @param actions         the finite set of manifest-declared actions valid for that resource
 * @param classifications the data-classification literals valid for that resource
 * @param attributes      the {@code R.attr.*} / {@code P.attr.*} attribute names a condition may name
 * @param roles           the principal roles a rule may name
 * @param approvedImports the {@code importDerivedRoles} modules a policy may import
 */
public record ManifestVocabulary(
        String resourceKind,
        Set<String> actions,
        Set<String> classifications,
        Set<String> attributes,
        Set<String> roles,
        Set<String> approvedImports) {

    public ManifestVocabulary {
        if (resourceKind == null || resourceKind.isBlank()) {
            throw new IllegalArgumentException("resourceKind must be set");
        }
        actions = Set.copyOf(actions);
        classifications = Set.copyOf(classifications);
        attributes = Set.copyOf(attributes);
        roles = Set.copyOf(roles);
        approvedImports = Set.copyOf(approvedImports);
    }
}
