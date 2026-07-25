package com.openwolf.iam.policystudio;

import org.junit.jupiter.api.Test;

import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.Assertions.assertThatCode;

/**
 * C4.5 — no stale diff. If the tenant's active bundle changes after a review is generated, approval is
 * BLOCKED until a fresh diff is computed against the new current bundle.
 */
class ReviewStalenessTest {

    @Test
    void currentBundleChangedRequiresRebase() {
        BundleSnapshot current = C4ConsequenceFixtures.bundle(C4ConsequenceFixtures.currentBody());
        BundleSnapshot candidate = C4ConsequenceFixtures.bundle(C4ConsequenceFixtures.candidateBody());

        InMemoryTenantActiveBundleRegistry registry = new InMemoryTenantActiveBundleRegistry();
        ConsequenceReviewSigner signer = ConsequenceReviewSigner.withKey(C4ConsequenceFixtures.SIGNING_KEY);
        ConsequenceApprovalService approvals = new ConsequenceApprovalService(signer, registry);

        ConsequenceReview review = C4ConsequenceFixtures.diffService().computeReview(
                C4ConsequenceFixtures.TENANT, C4ConsequenceFixtures.vocab(),
                current, candidate, C4ConsequenceFixtures.matrix(), C4ConsequenceFixtures.localPdp());

        // (1) active bundle == the diff's captured current bundle ⇒ approval is allowed.
        registry.setActiveBundle(C4ConsequenceFixtures.TENANT, current.bundleId());
        assertThatCode(() -> approvals.approve(
                review, "alice", Set.of("domain_owner"), ApprovalDecision.APPROVE))
                .doesNotThrowAnyException();

        // (2) the tenant's active bundle drifts (someone else promoted a change) ⇒ the review is STALE.
        registry.setActiveBundle(C4ConsequenceFixtures.TENANT, "bundle-some-other-active");
        assertThatThrownBy(() -> approvals.approve(
                review, "alice", Set.of("domain_owner"), ApprovalDecision.APPROVE))
                .isInstanceOf(StaleReviewException.class)
                .hasMessageContaining("stale");

        // (3) recompute the diff against the NEW current bundle ⇒ approval flows again.
        BundleSnapshot newCurrent = C4ConsequenceFixtures.bundle(
                C4ConsequenceFixtures.candidateBodyOneCellDifferent());
        registry.setActiveBundle(C4ConsequenceFixtures.TENANT, newCurrent.bundleId());
        ConsequenceReview rebased = C4ConsequenceFixtures.diffService().computeReview(
                C4ConsequenceFixtures.TENANT, C4ConsequenceFixtures.vocab(),
                newCurrent, candidate, C4ConsequenceFixtures.matrix(), C4ConsequenceFixtures.localPdp());
        assertThat(rebased.currentBundleId()).isEqualTo(newCurrent.bundleId());
        assertThatCode(() -> approvals.approve(
                rebased, "alice", Set.of("domain_owner"), ApprovalDecision.APPROVE))
                .doesNotThrowAnyException();
    }
}
