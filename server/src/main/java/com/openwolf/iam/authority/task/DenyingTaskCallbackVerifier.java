package com.openwolf.iam.authority.task;

import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/** Production default until a callback trust anchor is selected (decision D-3): no callback verifies. */
public final class DenyingTaskCallbackVerifier implements TaskCallbackVerifier {
    @Override
    public void verify(CallbackClaim claim, String signature) {
        throw new Rejected("no callback trust anchor is configured");
    }

    @Configuration
    static class DefaultCallbackVerifierConfiguration {
        @Bean
        @ConditionalOnMissingBean(TaskCallbackVerifier.class)
        TaskCallbackVerifier taskCallbackVerifier() {
            return new DenyingTaskCallbackVerifier();
        }
    }
}
