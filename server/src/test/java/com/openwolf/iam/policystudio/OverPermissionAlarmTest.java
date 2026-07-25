package com.openwolf.iam.policystudio;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * C4.2 — a widening candidate raises the loud over-permission alarm in the DATA. Every DENY→ALLOW cell
 * is present as a {@link DeltaDirection#WIDENED} delta, flagged {@code overPermission}, and the review
 * carries the alarm flag plus the "N principals GAIN access" count. (The DOM snapshot of the loud red
 * banner is deferred to the React UI story — this asserts the data the SPA renders.)
 */
class OverPermissionAlarmTest {

    @Test
    void denyToAllowIsFlaggedLoud() {
        ConsequenceReview review = C4ConsequenceFixtures.diffService().computeReview(
                C4ConsequenceFixtures.TENANT, C4ConsequenceFixtures.vocab(),
                C4ConsequenceFixtures.bundle(C4ConsequenceFixtures.currentBody()),
                C4ConsequenceFixtures.bundle(C4ConsequenceFixtures.candidateBody()),
                C4ConsequenceFixtures.matrix(), C4ConsequenceFixtures.localPdp());

        // The alarm flag is on the data, not just in UI chrome.
        assertThat(review.overPermissionAlarm()).isTrue();
        assertThat(review.principalsGainingAccess()).isEqualTo(3);

        // Every widening delta is a DENY→ALLOW, flagged as over-permission.
        assertThat(review.wideningDeltas()).hasSize(3).allSatisfy(d -> {
            assertThat(d.from()).isEqualTo(Effect.DENY);
            assertThat(d.to()).isEqualTo(Effect.ALLOW);
            assertThat(d.direction()).isEqualTo(DeltaDirection.WIDENED);
            assertThat(d.overPermission()).isTrue();
        });

        // Narrowing (access removed) is present but is NOT the over-permission alarm.
        assertThat(review.deltas()).filteredOn(d -> d.direction() == DeltaDirection.NARROWED)
                .hasSize(1)
                .allSatisfy(d -> assertThat(d.overPermission()).isFalse());
    }

    @Test
    void aPureNarrowingCandidateRaisesNoAlarm() {
        // Over the chat_user/rm-only matrix, swapping current↔candidate makes those cells ALLOW→DENY:
        // a pure narrowing (access removed), so NO over-permission alarm.
        ConsequenceReview review = C4ConsequenceFixtures.diffService().computeReview(
                C4ConsequenceFixtures.TENANT, C4ConsequenceFixtures.vocab(),
                C4ConsequenceFixtures.bundle(C4ConsequenceFixtures.candidateBody()),
                C4ConsequenceFixtures.bundle(C4ConsequenceFixtures.currentBody()),
                C4ConsequenceFixtures.smallerMatrix(), C4ConsequenceFixtures.localPdp());

        assertThat(review.overPermissionAlarm()).isFalse();
        assertThat(review.principalsGainingAccess()).isZero();
        assertThat(review.deltas()).isNotEmpty()
                .allSatisfy(d -> assertThat(d.direction()).isEqualTo(DeltaDirection.NARROWED));
    }
}
