package com.openwolf.iam.invocation;

import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Production default until a verifiable authorization mechanism is agreed (Phase 2.2): no evidence verifies, so no
 * invocation context can be established. Broker authentication, a caller-written Use Case or an unverified decision ID
 * are never sufficient on their own.
 */
public final class DenyingInvocationAuthorizationVerifier implements InvocationAuthorizationVerifier {
    @Override
    public Verified verify(EstablishmentClaim claim, String evidence) {
        throw new Rejected("no verifiable invocation authorization mechanism is configured");
    }

    @Configuration
    static class DefaultVerifierConfiguration {
        @Bean
        @ConditionalOnMissingBean(InvocationAuthorizationVerifier.class)
        InvocationAuthorizationVerifier invocationAuthorizationVerifier() {
            return new DenyingInvocationAuthorizationVerifier();
        }
    }
}
