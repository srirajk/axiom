package com.openwolf.iam.policystudio;

import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Mechanically fans each intent-implied ALLOW out into a fixed battery of negative probes (Axiom
 * Story C3.3). For EVERY {@link ProbeKind#POSITIVE} allow the oracle emits, this injector adds:
 *
 * <ol>
 *   <li>a {@link ProbeKind#CROSS_TENANT} variant — same principal + action, resource homed in a
 *       different tenant — expected DENY;</li>
 *   <li>a {@link ProbeKind#WRONG_SEGMENT} variant — same principal + action, but the
 *       classification/segment attribute set to an in-vocabulary value the intent did NOT sanction —
 *       expected DENY;</li>
 *   <li>a {@link ProbeKind#MISSING_ATTRIBUTE} variant — same principal + action, but the guard
 *       attribute omitted entirely — expected DENY (fail-closed; a policy that fails <em>open</em> on
 *       a missing attribute is exactly the bug this catches).</li>
 * </ol>
 *
 * These probes are the negatives a co-generated, self-consistent test suite would never write. They
 * are derived purely from the (positive) intent + manifest vocabulary — never from the candidate
 * policy — so they hold a wrong policy to the author's intent rather than to its own behaviour.
 *
 * <p>Deterministic: the injected values are a pure function of the positive expectation and the
 * vocabulary (the cross-tenant tenant is a stable suffix; the wrong-segment value is the
 * lexicographically-first in-vocabulary classification that differs from the sanctioned one).
 */
@Component
public class NegativeProbeInjector {

    /** Every positive ALLOW yields exactly this many negative probes. */
    public static final int PROBES_PER_ALLOW = 3;

    private static final String CROSS_TENANT_SUFFIX = "__other";

    /**
     * @param base  the oracle's positive (and any intent-implied explicit-DENY) expectations
     * @param attrs the manifest-grounded tenant + segment attribute names
     * @param vocab the closed vocabulary (its classifications supply the wrong-segment value)
     * @return {@code base} plus, for each positive ALLOW, the three negative probes above
     */
    public TestExpectationSet inject(TestExpectationSet base, ProbeAttributes attrs, ManifestVocabulary vocab) {
        List<Expectation> out = new ArrayList<>(base.expectations());
        for (Expectation e : base.expectations()) {
            if (e.kind() != ProbeKind.POSITIVE || e.expected() != Effect.ALLOW) {
                continue; // only fan out intent-implied allows
            }
            out.add(crossTenant(e));
            out.add(wrongSegment(e, attrs, vocab));
            out.add(missingAttribute(e, attrs));
        }
        return TestExpectationSet.of(out);
    }

    private Expectation crossTenant(Expectation e) {
        String otherTenant = (e.principalTenant() == null ? "tenant" : e.principalTenant()) + CROSS_TENANT_SUFFIX;
        return new Expectation(
                e.principalRoles(), e.principalTenant(), otherTenant,
                e.resourceAttrs(), e.action(), Effect.DENY, ProbeKind.CROSS_TENANT,
                e.label() + "::cross_tenant_denied");
    }

    private Expectation wrongSegment(Expectation e, ProbeAttributes attrs, ManifestVocabulary vocab) {
        Object sanctioned = e.resourceAttrs().get(attrs.segmentAttr());
        String wrong = pickDifferentClassification(vocab, sanctioned);
        Map<String, Object> perturbed = new LinkedHashMap<>(e.resourceAttrs());
        perturbed.put(attrs.segmentAttr(), wrong);
        return new Expectation(
                e.principalRoles(), e.principalTenant(), e.resourceTenant(),
                perturbed, e.action(), Effect.DENY, ProbeKind.WRONG_SEGMENT,
                e.label() + "::wrong_segment_denied");
    }

    private Expectation missingAttribute(Expectation e, ProbeAttributes attrs) {
        Map<String, Object> stripped = new LinkedHashMap<>(e.resourceAttrs());
        stripped.remove(attrs.segmentAttr());
        return new Expectation(
                e.principalRoles(), e.principalTenant(), e.resourceTenant(),
                stripped, e.action(), Effect.DENY, ProbeKind.MISSING_ATTRIBUTE,
                e.label() + "::missing_attribute_denied");
    }

    /** The lexicographically-first in-vocabulary classification that differs from the sanctioned one
     *  (a stable, deterministic choice). Falls back to a synthetic out-of-set value if the vocabulary
     *  has no alternative — that value is still an unsanctioned segment, so DENY remains the expectation. */
    private String pickDifferentClassification(ManifestVocabulary vocab, Object sanctioned) {
        Set<String> classes = vocab.classifications();
        return classes.stream()
                .filter(c -> !c.equals(sanctioned))
                .sorted()
                .findFirst()
                .orElse("__unsanctioned_segment");
    }
}
