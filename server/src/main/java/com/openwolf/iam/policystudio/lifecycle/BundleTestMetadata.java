package com.openwolf.iam.policystudio.lifecycle;

/**
 * The test evidence a candidate bundle was certified with (Axiom Story C5), folded into the bundle's
 * content-addressed identity. Two bundles that differ only in which fixture matrix / oracle certified
 * them are distinct bundles, so an examiner joining a decision back to its bundle also recovers the
 * exact test evidence that certified it (C5.6). This is a value, never a mutable field.
 *
 * @param fixtureSetHash the C4/C3 sampled matrix the certification diff was computed over
 * @param testCount      the number of probes exercised
 * @param oracle         the independent test-generation oracle id (C3) that produced the probes
 * @param pdpSourceId    the PDP that produced the certification decisions (e.g. {@code cerbos:0.53.0})
 */
public record BundleTestMetadata(String fixtureSetHash, int testCount, String oracle, String pdpSourceId) {

    public BundleTestMetadata {
        if (fixtureSetHash == null || fixtureSetHash.isBlank()) {
            throw new IllegalArgumentException("fixtureSetHash must be set");
        }
        if (pdpSourceId == null || pdpSourceId.isBlank()) {
            throw new IllegalArgumentException("pdpSourceId must be set");
        }
    }

    /** The order-stable canonical string folded into the bundle hash. */
    public String canonical() {
        return "fixtureSetHash=" + fixtureSetHash
                + ";testCount=" + testCount
                + ";oracle=" + (oracle == null ? "" : oracle)
                + ";pdpSourceId=" + pdpSourceId;
    }
}
