package com.openwolf.iam.authority.federation;

import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/** Production default until a provider profile and its trust anchor are selected (decision D-4). */
public final class DenyingWorkloadAssertionVerifier implements WorkloadAssertionVerifier {
    @Override
    public Verified verify(String profile, String assertion) {
        throw new Rejected("no workload-federation provider profile is configured");
    }

    @Configuration
    static class DefaultWorkloadAssertionVerifierConfiguration {
        @Bean
        @ConditionalOnMissingBean(WorkloadAssertionVerifier.class)
        WorkloadAssertionVerifier workloadAssertionVerifier() {
            return new DenyingWorkloadAssertionVerifier();
        }
    }
}
