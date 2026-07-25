package com.openwolf.iam.policystudio.lifecycle;

import org.junit.jupiter.api.Test;
import org.springframework.transaction.annotation.Transactional;

import static org.assertj.core.api.Assertions.assertThat;

/** Locks the C5 boundary: external candidate work is outside DB transactions. */
class PolicyPromotionTransactionBoundaryTest {

    @Test
    void orchestrationIsNonTransactionalAndLedgerOwnsOnlyShortBoundaries() throws Exception {
        assertThat(PolicyPromotionService.class.getMethod("promote", PromotionRequest.class)
                .isAnnotationPresent(Transactional.class)).isFalse();
        assertThat(PolicyPromotionService.class.getMethod("rollback", PromotionRequest.class)
                .isAnnotationPresent(Transactional.class)).isFalse();
        assertThat(PromotionLedger.class.getMethod("startOrResume", PromotionRequest.class)
                .isAnnotationPresent(Transactional.class)).isTrue();
        assertThat(PromotionLedger.class.getMethod("compareAndPromote", PromotionRequest.class,
                PromotionRecord.class, String.class).isAnnotationPresent(Transactional.class)).isTrue();
        assertThat(PromotionLedger.class.getMethod("markFailed", PromotionRecord.class, RuntimeException.class)
                .isAnnotationPresent(Transactional.class)).isTrue();
    }
}
