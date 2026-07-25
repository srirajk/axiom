package com.openwolf.iam.policystudio;

/**
 * One real PDP evaluation of one {@link FixtureCell} against one {@link BundleSnapshot} (Axiom Story
 * C4). The {@code effect} is the ground truth the diff is built from — it comes from a policy decision
 * point (the pinned Cerbos, or the in-process C3 fidelity evaluator), <b>never</b> from an LLM.
 *
 * @param cellLabel   the cell this decision answers (its {@link FixtureCell#label()})
 * @param effect      the decision the bundle returned for this cell
 * @param callId      the PDP call identifier (Cerbos suite/test id, or the fidelity-evaluator call id)
 * @param rawResponse the raw PDP response fragment, retained with the review for audit/replay
 */
public record PdpDecision(String cellLabel, Effect effect, String callId, String rawResponse) {

    public PdpDecision {
        if (cellLabel == null || cellLabel.isBlank()) {
            throw new IllegalArgumentException("cellLabel must be set");
        }
        if (effect == null) {
            throw new IllegalArgumentException("effect must be set");
        }
    }
}
