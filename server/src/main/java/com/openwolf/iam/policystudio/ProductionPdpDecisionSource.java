package com.openwolf.iam.policystudio;

import org.springframework.stereotype.Component;

import java.util.List;

/**
 * Production consequence-review truth source. This seam deliberately has no local-evaluator fallback:
 * if the pinned Cerbos runtime cannot evaluate a candidate, the review is refused rather than computed
 * from a Java approximation of Cerbos semantics.
 */
@Component
public class ProductionPdpDecisionSource implements PdpDecisionSource {

    private final CerbosBatchDecisionSource cerbos;

    public ProductionPdpDecisionSource(CerbosBatchDecisionSource cerbos) {
        this.cerbos = cerbos;
    }

    @Override
    public String sourceId() {
        return cerbos.sourceId();
    }

    @Override
    public boolean isAvailable() {
        return cerbos.isAvailable();
    }

    @Override
    public PdpBatchResult evaluate(BundleSnapshot bundle, List<FixtureCell> cells) {
        if (!cerbos.isAvailable()) {
            throw new IllegalStateException(
                    "pinned Cerbos is unavailable; refusing to compute a consequence review from an approximation");
        }
        return cerbos.evaluate(bundle, cells);
    }
}
