package com.openwolf.iam.authority.federation;

import java.time.Instant;

/**
 * Phase 3.11/3.12 adapter for a selected provider profile (a hosted-Agent platform or a partner's workload identity
 * system). It verifies an assertion's signature against that provider's trust anchor and returns what the provider
 * says about the <em>workload</em> — never about a human. No profile is selected yet (decision D-4), so the production
 * default denies every assertion ({@link DenyingWorkloadAssertionVerifier}).
 */
public interface WorkloadAssertionVerifier {

    /** Verified, provider-asserted facts. Axiom enforces audience, lifetime and replay itself. */
    record Verified(String issuer, String subject, String audience, Instant issuedAt, Instant expiresAt, String jti) {}

    final class Rejected extends RuntimeException {
        public Rejected(String reason) { super(reason, null, false, false); }
    }

    Verified verify(String profile, String assertion);
}
