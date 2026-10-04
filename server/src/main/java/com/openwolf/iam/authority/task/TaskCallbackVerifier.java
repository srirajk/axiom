package com.openwolf.iam.authority.task;

import java.time.Instant;
import java.util.UUID;

/**
 * Phase 3.5 adapter that authenticates an inbound workflow/provider callback. The trust anchor (key distribution,
 * algorithm, provider identity) is a per-provider decision, so the production default denies everything
 * ({@link DenyingTaskCallbackVerifier}). An implementation must bind the signature to every field of
 * {@link CallbackClaim}: a signature for one task, audience, time, nonce, event or body must not verify for another.
 */
public interface TaskCallbackVerifier {

    record CallbackClaim(String tenantId, String provider, UUID taskId, String audience, Instant issuedAt,
                         String nonce, String eventType, String bodyDigest) {}

    final class Rejected extends RuntimeException {
        public Rejected(String reason) { super(reason, null, false, false); }
    }

    /** Returns normally only when {@code signature} proves {@code claim} came from {@code claim.provider()}. */
    void verify(CallbackClaim claim, String signature);
}
