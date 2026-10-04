package com.openwolf.iam.invocation;

import java.time.Instant;
import java.util.Set;
import java.util.UUID;

/**
 * Phase 2.2 adapter: verifies the authorization a trusted broker presents to establish an invocation context. The
 * mechanism (format, trust anchor, freshness) is not yet agreed, so the production implementation denies everything
 * ({@link DenyingInvocationAuthorizationVerifier}). An implementation must bind the evidence to every field of
 * {@link EstablishmentClaim}: evidence verified for one subject, Use Case, destination or scope set must not verify
 * for another.
 */
public interface InvocationAuthorizationVerifier {

    /** Everything Axiom has already verified about the requested establishment. */
    record EstablishmentClaim(String tenantId, String brokerClientId, String securityScope, String subject,
                              String rootSessionId, UUID useCaseApplicationId, UUID entryWorkloadId,
                              String destinationAudience, Set<String> requestedScopes, Instant requestedDeadline) {}

    /** The verifier's decision: a non-secret reference for audit, approved scopes and the decision's validity. */
    record Verified(String reference, Set<String> approvedScopes, Instant notAfter) {}

    /** Thrown for any evidence that does not verify; the message is never returned to the caller. */
    final class Rejected extends RuntimeException {
        public Rejected(String reason) { super(reason, null, false, false); }
    }

    Verified verify(EstablishmentClaim claim, String evidence);
}
