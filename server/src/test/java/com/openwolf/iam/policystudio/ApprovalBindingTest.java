package com.openwolf.iam.policystudio;

import org.junit.jupiter.api.Test;

import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * C4.6 — an approval cryptographically binds the EXACT machine consequences. The signed record commits
 * to the {@code consequenceReviewHash}, which in turn binds the tenant, both bundle ids, the sampled
 * matrix, and the canonical machine delta. Changing the candidate bundle, the current bundle, the
 * fixture set, or a SINGLE delta cell changes the review hash and invalidates the approval; changing
 * only the display wording does NOT.
 */
class ApprovalBindingTest {

    private ConsequenceReview review(BundleSnapshot current, BundleSnapshot candidate,
                                     ConsequenceFixtureMatrix matrix) {
        return C4ConsequenceFixtures.diffService().computeReview(
                C4ConsequenceFixtures.TENANT, C4ConsequenceFixtures.vocab(),
                current, candidate, matrix, C4ConsequenceFixtures.localPdp());
    }

    @Test
    void approvalBindsExactConsequences() {
        BundleSnapshot current = C4ConsequenceFixtures.bundle(C4ConsequenceFixtures.currentBody());
        BundleSnapshot candidate = C4ConsequenceFixtures.bundle(C4ConsequenceFixtures.candidateBody());
        ConsequenceFixtureMatrix matrix = C4ConsequenceFixtures.matrix();

        InMemoryTenantActiveBundleRegistry registry = new InMemoryTenantActiveBundleRegistry();
        registry.setActiveBundle(C4ConsequenceFixtures.TENANT, current.bundleId());
        ConsequenceReviewSigner signer = ConsequenceReviewSigner.withKey(C4ConsequenceFixtures.SIGNING_KEY);
        ConsequenceApprovalService approvals = new ConsequenceApprovalService(signer, registry);

        ConsequenceReview review = review(current, candidate, matrix);
        ConsequenceApprovalRecord record = approvals.approve(
                review, "carol", Set.of("domain_owner"), ApprovalDecision.APPROVE);

        // The record signs the exact review hash and authorizes THIS review's promotion.
        assertThat(record.consequenceReviewHash()).isEqualTo(review.consequenceReviewHash());
        assertThat(record.signature()).isNotBlank();
        assertThat(approvals.authorizesPromotion(record, review)).isTrue();

        // (a) Change the CANDIDATE bundle → different truth → different hash → approval no longer binds.
        ConsequenceReview differentCandidate = review(current,
                C4ConsequenceFixtures.bundle(C4ConsequenceFixtures.candidateBodyOneCellDifferent()), matrix);
        assertThat(differentCandidate.consequenceReviewHash()).isNotEqualTo(review.consequenceReviewHash());
        assertThat(approvals.authorizesPromotion(record, differentCandidate)).isFalse();

        // (b) Change ONE delta cell only (candidate that differs in a single cell) → new hash.
        //     (differentCandidate above differs from candidate by exactly the rm/chat_user membership cell.)
        assertThat(differentCandidate.deltas()).hasSizeLessThan(review.deltas().size());

        // (c) Change the CURRENT bundle → different baseline → different hash → no longer binds.
        BundleSnapshot otherCurrent = C4ConsequenceFixtures.bundle(
                C4ConsequenceFixtures.candidateBodyOneCellDifferent());
        ConsequenceReview differentCurrent = review(otherCurrent, candidate, matrix);
        assertThat(differentCurrent.consequenceReviewHash()).isNotEqualTo(review.consequenceReviewHash());
        assertThat(approvals.authorizesPromotion(record, differentCurrent)).isFalse();

        // (d) Change the FIXTURE SET (smaller matrix) → different fixtureSetHash → different hash.
        ConsequenceReview differentMatrix = review(current, candidate, C4ConsequenceFixtures.smallerMatrix());
        assertThat(differentMatrix.fixtureSetHash()).isNotEqualTo(review.fixtureSetHash());
        assertThat(differentMatrix.consequenceReviewHash()).isNotEqualTo(review.consequenceReviewHash());
        assertThat(approvals.authorizesPromotion(record, differentMatrix)).isFalse();

        // (e) Change ONLY the display wording → SAME hash → approval STILL binds.
        ConsequenceReview reworded = review.withProse("Totally different human wording, same truth.");
        assertThat(reworded.consequenceReviewHash()).isEqualTo(review.consequenceReviewHash());
        assertThat(approvals.authorizesPromotion(record, reworded)).isTrue();

        // Tamper-evidence: the signature is a valid HMAC over the record's payload …
        assertThat(signer.verify(record.signingPayload(), record.signature())).isTrue();
        // … but the SAME signature over a mutated payload (review hash flipped) no longer verifies.
        ConsequenceApprovalRecord tampered = new ConsequenceApprovalRecord(
                record.tenantId(), record.currentBundleId(), record.candidateBundleId(),
                record.fixtureSetHash(), "crh-tampered", record.overPermissionAlarm(),
                record.approverId(), record.approverRoles(), record.decision(),
                record.signature(), record.signedAt());
        assertThat(signer.verify(tampered.signingPayload(), tampered.signature())).isFalse();
        assertThat(approvals.authorizesPromotion(tampered, review)).isFalse();
    }
}
