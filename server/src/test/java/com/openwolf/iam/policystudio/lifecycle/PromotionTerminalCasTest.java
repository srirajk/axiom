package com.openwolf.iam.policystudio.lifecycle;

import com.openwolf.iam.tenancy.ActiveTenantDirectory;
import org.junit.jupiter.api.Test;

import static org.mockito.Mockito.*;

/** Locks the terminal promotion invariant: a late failure cannot overwrite PROMOTED. */
class PromotionTerminalCasTest {

    @Test
    void failureUsesPromotedGuardedUpdate() {
        PromotionRepository promotions = mock(PromotionRepository.class);
        PromotionRecord operation = new PromotionRecord(
                "promotion-key", "tenant-a", "old", "new", "review-hash", "approver",
                PromotionRecord.Kind.PROMOTION);
        PromotionLedger ledger = new PromotionLedger(mock(ActiveTenantDirectory.class), promotions,
                mock(PolicyBundleRepository.class), mock(ApprovalRepository.class));

        ledger.markFailed(operation, new IllegalStateException("late external failure"));

        verify(promotions).markFailedIfNotPromoted("promotion-key", "java.lang.IllegalStateException: late external failure",
                PromotionRecord.Status.FAILED, PromotionRecord.Status.PROMOTED);
        verifyNoMoreInteractions(promotions);
    }
}
