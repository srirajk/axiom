package com.openwolf.iam.policystudio;

/**
 * One business consequence a candidate bundle would introduce (Axiom Story C4): a single cell whose
 * real PDP decision changed between the current and candidate snapshots, rendered as a business
 * consequence over the tenant's manifest entity vocabulary.
 *
 * <p>{@code from}/{@code to} are the real decisions from the two immutable snapshots (never an LLM's
 * opinion). {@link DeltaDirection#WIDENED} (DENY→ALLOW) sets {@code overPermission} — the loud
 * "N principals GAIN access" alarm. The {@code businessConsequence} phrasing is composed from
 * {@link ManifestVocabulary} terms ({@code resourceKind}, roles, actions), so a non-engineer reads a
 * consequence in their own domain vocabulary and no domain literal is hardcoded (World B).
 *
 * @param cell                the principal×resource×action cell whose decision changed
 * @param from                the current bundle's decision
 * @param to                  the candidate bundle's decision
 * @param direction           WIDENED (over-permission) or NARROWED (access removed)
 * @param overPermission      {@code true} iff the direction is WIDENED — the alarm flag on the data
 * @param businessConsequence the manifest-vocabulary phrasing shown to the approver
 */
public record ConsequenceDelta(
        FixtureCell cell,
        Effect from,
        Effect to,
        DeltaDirection direction,
        boolean overPermission,
        String businessConsequence) {

    public ConsequenceDelta {
        if (from == to) {
            throw new IllegalArgumentException("a delta must be a change; from == to is not a delta");
        }
        if (direction == null) {
            throw new IllegalArgumentException("direction must be set");
        }
    }

    /** The canonical, machine-readable row this delta contributes to the review hash. */
    public String canonicalRow() {
        return cell.canonicalKey() + "|EFFECT_" + from + "->EFFECT_" + to;
    }
}
