package com.openwolf.iam.policystudio;

import org.junit.jupiter.api.Test;

import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Axiom H3 — {@link ConsequenceApprovalService#approve} enforces the approver gate at the SERVICE from
 * VERIFIED identity, independent of (and behind) the controller:
 *
 * <ul>
 *   <li>self-approval is rejected — the author is read from the server-recorded {@link ReviewAuthorRegistry},
 *       never a caller-supplied id;</li>
 *   <li>a {@code platform_admin} without an explicit approver role is rejected (no auto-approval);</li>
 *   <li>an approver from a different tenant is rejected;</li>
 *   <li>a null approver identity fails closed (never a skipped check).</li>
 * </ul>
 *
 * A legitimate approver in the review's tenant, holding an approver role and NOT the author, still signs.
 */
class ConsequenceApprovalSoDTest {

    /** A stateful in-memory author registry — records the verified author of a review by (tenant, hash). */
    private static final class InMemoryAuthors implements ReviewAuthorRegistry {
        private final Map<String, String> byKey = new ConcurrentHashMap<>();

        void record(String tenantId, String reviewHash, String author) {
            byKey.put(tenantId + "|" + reviewHash, author);
        }

        @Override
        public Optional<String> authorFor(String tenantId, String consequenceReviewHash) {
            return Optional.ofNullable(byKey.get(tenantId + "|" + consequenceReviewHash));
        }
    }

    private ConsequenceReview review() {
        BundleSnapshot current = C4ConsequenceFixtures.bundle(C4ConsequenceFixtures.currentBody());
        BundleSnapshot candidate = C4ConsequenceFixtures.bundle(C4ConsequenceFixtures.candidateBody());
        return C4ConsequenceFixtures.diffService().computeReview(
                C4ConsequenceFixtures.TENANT, C4ConsequenceFixtures.vocab(),
                current, candidate, C4ConsequenceFixtures.matrix(), C4ConsequenceFixtures.localPdp());
    }

    private ConsequenceApprovalService service(InMemoryAuthors authors) {
        InMemoryTenantActiveBundleRegistry active = new InMemoryTenantActiveBundleRegistry();
        // Keep the review non-stale so the H3 gate is what fires (not the C4.5 staleness check).
        active.setActiveBundle(C4ConsequenceFixtures.TENANT, review().currentBundleId());
        ConsequenceReviewSigner signer = ConsequenceReviewSigner.withKey(C4ConsequenceFixtures.SIGNING_KEY);
        return new ConsequenceApprovalService(signer, active, authors, Set.of("policy_approver"));
    }

    @Test
    void selfApprovalIsRejected() {
        ConsequenceReview review = review();
        InMemoryAuthors authors = new InMemoryAuthors();
        authors.record(review.tenantId(), review.consequenceReviewHash(), "alice");
        ConsequenceApprovalService svc = service(authors);

        // 'alice' authored the review and is now the approver — self-approval blocked from the recorded author.
        assertThatThrownBy(() -> svc.approve(review,
                new ApproverIdentity(C4ConsequenceFixtures.TENANT, "alice", Set.of("policy_approver")),
                ApprovalDecision.APPROVE))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("separation of duties");
    }

    @Test
    void platformAdminWithoutApproverRoleIsRejected() {
        ConsequenceReview review = review();
        ConsequenceApprovalService svc = service(new InMemoryAuthors());

        assertThatThrownBy(() -> svc.approve(review,
                new ApproverIdentity(C4ConsequenceFixtures.TENANT, "root", Set.of("platform_admin")),
                ApprovalDecision.APPROVE))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("platform_admin");
    }

    @Test
    void approverFromADifferentTenantIsRejected() {
        ConsequenceReview review = review();
        ConsequenceApprovalService svc = service(new InMemoryAuthors());

        assertThatThrownBy(() -> svc.approve(review,
                new ApproverIdentity("other-tenant", "bob", Set.of("policy_approver")),
                ApprovalDecision.APPROVE))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("own tenant");
    }

    @Test
    void nullApproverFailsClosed() {
        ConsequenceReview review = review();
        ConsequenceApprovalService svc = service(new InMemoryAuthors());

        assertThatThrownBy(() -> svc.approve(review,
                new ApproverIdentity(C4ConsequenceFixtures.TENANT, null, Set.of("policy_approver")),
                ApprovalDecision.APPROVE))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("null");
    }

    @Test
    void legitimateApproverInTenantSigns() {
        ConsequenceReview review = review();
        InMemoryAuthors authors = new InMemoryAuthors();
        authors.record(review.tenantId(), review.consequenceReviewHash(), "alice"); // author is alice
        ConsequenceApprovalService svc = service(authors);

        // 'bob' (≠ author), an approver-role holder in the review's tenant, signs successfully.
        assertThatCode(() -> {
            ConsequenceApprovalRecord rec = svc.approve(review,
                    new ApproverIdentity(C4ConsequenceFixtures.TENANT, "bob", Set.of("policy_approver")),
                    ApprovalDecision.APPROVE);
            assertThat(rec.approverId()).isEqualTo("bob");
            assertThat(rec.signature()).isNotBlank();
            assertThat(svc.authorizesPromotion(rec, review)).isTrue();
        }).doesNotThrowAnyException();
    }
}
