package com.openwolf.iam.policystudio;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * C4.1 (THE HEADLINE) — the consequence delta comes from the PDP, never from the LLM. The diff is
 * computed from real policy decisions ({@link PdpDecisionSource}); the LLM prose seam is stubbed to
 * ERROR, and the delta set is STILL correct. If the diff depended on the LLM, this test would go red.
 */
class ConsequenceDiffFromRealPdpTest {

    @Test
    void deltasComeFromCerbosNotLlm() {
        ConsequenceDiffService svc = C4ConsequenceFixtures.diffService();
        BundleSnapshot current = C4ConsequenceFixtures.bundle(C4ConsequenceFixtures.currentBody());
        BundleSnapshot candidate = C4ConsequenceFixtures.bundle(C4ConsequenceFixtures.candidateBody());

        // Truth comes from the PDP source (never an LLM).
        ConsequenceReview review = svc.computeReview(
                C4ConsequenceFixtures.TENANT, C4ConsequenceFixtures.vocab(),
                current, candidate, C4ConsequenceFixtures.matrix(), C4ConsequenceFixtures.localPdp());

        // The delta set is fully computed WITHOUT any LLM: 3 widen (chat_user invoke+membership,
        // rm invoke) + 1 narrow (domain_admin register); platform_admin invoke unchanged.
        assertThat(review.deltas()).hasSize(4);
        assertThat(review.wideningDeltas()).hasSize(3);
        assertThat(review.provenance().sourceId()).isEqualTo(LocalPdpDecisionSource.SOURCE_ID);
        String hashBefore = review.consequenceReviewHash();

        // Now run the LLM prose seam — stubbed to THROW. The review is STILL correct; prose is absent.
        ConsequenceReview afterProse = svc.attachProse(review, C4ConsequenceFixtures.erroringProse());

        assertThat(afterProse.displayProse()).isNull();               // LLM failed → no prose
        assertThat(afterProse.deltas()).hasSize(4);                   // …but the delta set is intact
        assertThat(afterProse.wideningDeltas()).hasSize(3);
        assertThat(afterProse.overPermissionAlarm()).isTrue();
        assertThat(afterProse.consequenceReviewHash()).isEqualTo(hashBefore); // unchanged by the LLM

        // And the truth values match a straight PDP evaluation of both snapshots (no LLM in that path).
        PdpBatchResult beforeBatch = review.provenance().currentBatch();
        PdpBatchResult afterBatch = review.provenance().candidateBatch();
        assertThat(beforeBatch.byCell().get("chatUser_invoke")).isEqualTo(Effect.DENY);
        assertThat(afterBatch.byCell().get("chatUser_invoke")).isEqualTo(Effect.ALLOW);
        assertThat(beforeBatch.byCell().get("platformAdmin_invoke")).isEqualTo(Effect.ALLOW);
        assertThat(afterBatch.byCell().get("platformAdmin_invoke")).isEqualTo(Effect.ALLOW);
    }
}
