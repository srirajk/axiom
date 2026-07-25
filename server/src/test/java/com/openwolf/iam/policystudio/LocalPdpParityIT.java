package com.openwolf.iam.policystudio;

import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * H8 / bug-292 regression. The original held test correctly proved that the local Java evaluator
 * diverges from Cerbos. The selected fix is not to imitate more Cerbos semantics in Java: production
 * reviews now use {@link ProductionPdpDecisionSource}. This test keeps the local divergence visible,
 * while requiring the source wired into the production controller to agree cell-for-cell with an
 * independent pinned-Cerbos source.
 */
class LocalPdpParityIT {

    private record NamedBundle(String label, String yaml) {}

    private static List<NamedBundle> bundles() {
        return List.of(
                new NamedBundle("c4_c5_current", C4ConsequenceFixtures.currentBody()),
                new NamedBundle("c4_c5_candidate", C4ConsequenceFixtures.candidateBody()),
                new NamedBundle("c4_candidate_one_cell_different",
                        C4ConsequenceFixtures.candidateBodyOneCellDifferent()),
                new NamedBundle("compliant_acme_golden", PolicyStudioFixtures.compliantAcme()));
    }

    @Test
    void productionSourceUsesRealCerbosAndMatchesEveryRealDecision() {
        CanonicalPolicyWriter writer = new CanonicalPolicyWriter();
        String base = PolicyStudioFixtures.baseBundleDir().toString();
        CerbosBatchDecisionSource productionCerbos =
                new CerbosBatchDecisionSource("ghcr.io/cerbos/cerbos:0.53.0", 120, "0.53.0", base, writer);
        CerbosBatchDecisionSource independentCerbos =
                new CerbosBatchDecisionSource("ghcr.io/cerbos/cerbos:0.53.0", 120, "0.53.0", base, writer);
        requireRealPdp(productionCerbos);

        ProductionPdpDecisionSource production = new ProductionPdpDecisionSource(productionCerbos);
        PdpDecisionSource local = C4ConsequenceFixtures.localPdp();
        List<FixtureCell> cells = C4ConsequenceFixtures.matrix().cells();
        List<String> productionDivergences = new ArrayList<>();
        List<String> knownLocalDivergences = new ArrayList<>();

        for (NamedBundle named : bundles()) {
            BundleSnapshot snapshot = C4ConsequenceFixtures.bundle(named.yaml());
            Map<String, Effect> productionDecisions = production.evaluate(snapshot, cells).byCell();
            Map<String, Effect> realDecisions = independentCerbos.evaluate(snapshot, cells).byCell();
            Map<String, Effect> localDecisions = local.evaluate(snapshot, cells).byCell();
            for (FixtureCell cell : cells) {
                Effect actual = productionDecisions.get(cell.label());
                Effect real = realDecisions.get(cell.label());
                Effect approximated = localDecisions.get(cell.label());
                if (actual != real) {
                    productionDivergences.add(named.label() + "/" + cell.label()
                            + " production=" + actual + " real=" + real);
                }
                if (approximated != real) {
                    knownLocalDivergences.add(named.label() + "/" + cell.label()
                            + " local=" + approximated + " real=" + real);
                }
            }
        }

        assertThat(production.sourceId()).isEqualTo("cerbos:0.53.0");
        assertThat(productionDivergences)
                .as("the source used by production reviews must match pinned Cerbos on every cell")
                .isEmpty();
        assertThat(knownLocalDivergences)
                .as("bug-292 remains documented: the retired local evaluator is not Cerbos truth")
                .isNotEmpty();

        // The studio review routes (StudioReviewController + StudioGroundingController) both derive
        // grounding and run consequence diffs through GroundedStudioReviewService — so the production
        // PDP truth (never the retired local evaluator) must be wired THERE.
        Class<?>[] reviewServiceDependencies = Arrays.stream(GroundedStudioReviewService.class.getConstructors())
                .findFirst().orElseThrow().getParameterTypes();
        assertThat(reviewServiceDependencies)
                .contains(ProductionPdpDecisionSource.class)
                .doesNotContain(LocalPdpDecisionSource.class);
    }

    private static void requireRealPdp(CerbosBatchDecisionSource cerbos) {
        boolean available = cerbos.isAvailable();
        boolean requiredInCi = Boolean.parseBoolean(
                System.getenv().getOrDefault("CONDUIT_DOCKER_REQUIRED", "false"));
        if (requiredInCi) {
            assertThat(available)
                    .as("CONDUIT_DOCKER_REQUIRED=true but pinned Cerbos is unavailable; H8 must run")
                    .isTrue();
        } else {
            Assumptions.assumeTrue(available, "pinned Cerbos is unavailable; skipping H8 locally");
        }
    }
}
