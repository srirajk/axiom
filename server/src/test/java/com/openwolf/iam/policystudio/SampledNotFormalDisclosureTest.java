package com.openwolf.iam.policystudio;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * C4.4 — the "sampled, not formal" limitation is a first-class field on the review DATA, not merely UI
 * chrome. The diff is an empirical measurement over a finite fixture matrix; the review says so, so an
 * approver is told the epistemic status of what they are signing.
 */
class SampledNotFormalDisclosureTest {

    @Test
    void surfaceStatesLimitation() {
        ConsequenceFixtureMatrix matrix = C4ConsequenceFixtures.matrix();
        ConsequenceReview review = C4ConsequenceFixtures.diffService().computeReview(
                C4ConsequenceFixtures.TENANT, C4ConsequenceFixtures.vocab(),
                C4ConsequenceFixtures.bundle(C4ConsequenceFixtures.currentBody()),
                C4ConsequenceFixtures.bundle(C4ConsequenceFixtures.candidateBody()),
                matrix, C4ConsequenceFixtures.localPdp());

        SampledDisclosure disclosure = review.disclosure();
        assertThat(disclosure).isNotNull();
        assertThat(disclosure.sampledNotFormal()).isTrue();
        assertThat(disclosure.sampledCellCount()).isEqualTo(matrix.cells().size());
        assertThat(disclosure.statement())
                .containsIgnoringCase("sampled")
                .containsIgnoringCase("not a formal proof");
    }
}
