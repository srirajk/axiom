package com.openwolf.iam.policystudio;

/**
 * The manifest-grounded attribute names the {@link NegativeProbeInjector} mutates when it fans a
 * positive ALLOW out into negative probes (Axiom Story C3). World B: these names are NOT hardcoded
 * domain literals in the injector — they are supplied per tenant from the manifest vocabulary (the
 * tenant discriminator attribute and the data-classification/segment attribute), exactly as C2's
 * {@link ManifestVocabulary} is supplied. The injector only knows "the tenant key" and "the segment
 * key"; the concrete strings live in config/fixtures.
 *
 * @param tenantAttr  the attribute name carrying the tenant a principal/resource is homed in
 * @param segmentAttr the attribute name carrying the data-classification / segment guard the intent
 *                    may constrain (the attribute a {@link ProbeKind#WRONG_SEGMENT} probe perturbs and
 *                    a {@link ProbeKind#MISSING_ATTRIBUTE} probe omits)
 */
public record ProbeAttributes(String tenantAttr, String segmentAttr) {

    public ProbeAttributes {
        if (tenantAttr == null || tenantAttr.isBlank() || segmentAttr == null || segmentAttr.isBlank()) {
            throw new IllegalArgumentException("tenantAttr and segmentAttr must be set");
        }
    }
}
