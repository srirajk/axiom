package com.openwolf.iam.policystudio.lifecycle;

import com.openwolf.iam.policystudio.ConsequenceApprovalRecord;
import com.openwolf.iam.policystudio.ConsequenceReview;
import com.openwolf.iam.tenancy.ActiveTenantDirectory;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * C5.5 — a promotion cannot split one request across policy versions. A request captures the active
 * bundle id ONCE at its start (A2's {@code activePolicyVersion}); every check within the request reads
 * that pin. A promotion that advances the live directory mid-request does NOT change what the in-flight
 * request sees — its checks all resolve to the version captured at request start.
 */
class PromotionAtomicityTest {

    @Test
    void requestNeverMixesPolicyVersions() {
        PolicyBundle current = C5LifecycleFixtures.bundle(C5LifecycleFixtures.currentBody(), C5LifecycleFixtures.matrixHash());
        PolicyBundle candidate = C5LifecycleFixtures.bundle(C5LifecycleFixtures.candidateBody(), C5LifecycleFixtures.matrixHash());
        ConsequenceReview review = C5LifecycleFixtures.review(current, candidate);
        ConsequenceApprovalRecord approval = C5LifecycleFixtures.approve(review, "sec-reviewer-01");

        ActiveTenantDirectory dir = C5LifecycleFixtures.directory();
        dir.activate(C5LifecycleFixtures.TENANT, current.bundleId());

        PolicyPromotionService svc = C5LifecycleFixtures.promotionService(
                dir, C5LifecycleFixtures.promotionRepo(), C5LifecycleFixtures.bundleRepo(),
                C5LifecycleFixtures.approvalRepo(), C5LifecycleFixtures.passingProbe(), "commit-1");

        // A multi-check request begins: capture the active version ONCE.
        RequestPolicyVersionPin pin = RequestPolicyVersionPin.capture(C5LifecycleFixtures.TENANT, dir);
        assertThat(pin.activePolicyVersion()).isEqualTo(current.bundleId());

        List<String> versionsUsedByChecks = new ArrayList<>();
        // Check 1 and 2 happen before the promotion.
        versionsUsedByChecks.add(pin.activePolicyVersion());
        versionsUsedByChecks.add(pin.activePolicyVersion());

        // A promotion lands mid-request — the live directory advances to the candidate.
        PromotionReceipt receipt = svc.promote(new PromotionRequest(
                candidate, review, approval, "promo-key-atomic", PromotionRecord.Kind.PROMOTION));
        assertThat(receipt.toBundleId()).isEqualTo(candidate.bundleId());
        assertThat(dir.find(C5LifecycleFixtures.TENANT)).hasValue(candidate.bundleId());

        // Checks 3 and 4 happen AFTER the promotion — still resolve to the captured version.
        versionsUsedByChecks.add(pin.activePolicyVersion());
        versionsUsedByChecks.add(pin.activePolicyVersion());

        // Every check in the request used exactly the version captured at request start — no mixing.
        assertThat(versionsUsedByChecks).containsOnly(current.bundleId());
        // And the pin is genuinely stale relative to the now-live directory (the promotion did happen).
        assertThat(pin.activePolicyVersion()).isNotEqualTo(dir.find(C5LifecycleFixtures.TENANT).orElseThrow());
    }
}
