package com.openwolf.iam.policystudio;

import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * The result of evaluating an entire {@link ConsequenceFixtureMatrix} against ONE
 * {@link BundleSnapshot} through a {@link PdpDecisionSource} (Axiom Story C4). The diff service holds
 * BOTH batches (current + candidate) as evidence: the bundle id under evaluation, the PDP source id,
 * every per-cell decision, its call id and its raw response. This is what makes the delta auditable —
 * an operator can re-run the exact batch and reproduce every truth value.
 *
 * @param bundleId  the immutable snapshot these decisions were computed against
 * @param sourceId  the PDP that produced them (e.g. {@code cerbos:0.53.0} or the fidelity evaluator)
 * @param decisions the per-cell decisions, in matrix order
 */
public record PdpBatchResult(String bundleId, String sourceId, List<PdpDecision> decisions) {

    public PdpBatchResult {
        decisions = List.copyOf(decisions);
    }

    /** Index the decisions by cell label for the diff join. */
    public Map<String, Effect> byCell() {
        return decisions.stream().collect(Collectors.toMap(
                PdpDecision::cellLabel, PdpDecision::effect, (a, b) -> a));
    }
}
