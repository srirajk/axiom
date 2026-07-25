package com.openwolf.iam.policystudio;

/**
 * The first-class "sampled, not formal" disclosure carried by every {@link ConsequenceReview} (Axiom
 * Story C4). The consequence diff is computed over a FINITE, SAMPLED principal×resource×action fixture
 * matrix — it is an empirical measurement, not a formal proof that the candidate differs from the
 * current bundle in exactly these ways and no others. The review states this in the data (never only
 * in UI chrome), so an approver is told, structurally, the epistemic status of what they are signing.
 *
 * @param sampledNotFormal always {@code true} — this surface is sampled, never a formal proof
 * @param sampledCellCount the number of cells the matrix actually evaluated
 * @param statement        the human-readable limitation statement
 */
public record SampledDisclosure(boolean sampledNotFormal, int sampledCellCount, String statement) {

    public static SampledDisclosure over(int sampledCellCount) {
        return new SampledDisclosure(
                true,
                sampledCellCount,
                "This consequence diff is computed over a sampled fixture matrix of "
                        + sampledCellCount + " principal×resource×action cells evaluated against the real "
                        + "policy decision point. It is an empirical measurement of the decision delta on "
                        + "those cells, NOT a formal proof that no other decision differs. Widen the matrix "
                        + "to raise assurance; it can never be exhaustive.");
    }
}
