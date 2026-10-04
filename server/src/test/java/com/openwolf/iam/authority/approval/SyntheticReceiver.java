package com.openwolf.iam.authority.approval;

import com.fasterxml.jackson.databind.JsonNode;

import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Test-only receiver implementing the Phase 3.8 receiver contract. Axiom guarantees one token per approval; this
 * receiver owns the business record and guarantees one effect per approval:
 * <ol>
 *   <li>validate the token with Axiom (introspection): active, audience = this receiver, token_use = approved_action;</li>
 *   <li>recompute the canonical digest of the request it is about to execute and require it to equal
 *       {@code action_digest} and {@code action_type} (a changed amount/recipient/operation is refused);</li>
 *   <li>execute at most once per {@code approval_id} (its business idempotency key), atomically; a retry with the same
 *       approval and digest returns the established outcome without a second effect.</li>
 * </ol>
 * The in-memory store stands in for the receiver's own durable store; Axiom never holds business records.
 */
final class SyntheticReceiver {
    record Outcome(String executionId, String approvalId, String digest) {}

    enum Refusal { INACTIVE_TOKEN, WRONG_AUDIENCE, NOT_AN_APPROVED_ACTION, DIGEST_MISMATCH }

    record Result(Outcome outcome, Refusal refusal) {}

    interface Introspection { JsonNode introspect(String token) throws Exception; }

    private final String audience;
    private final Introspection axiom;
    private final Map<String, Outcome> executions = new ConcurrentHashMap<>();
    final AtomicInteger effects = new AtomicInteger();

    SyntheticReceiver(String audience, Introspection axiom) {
        this.audience = audience;
        this.axiom = axiom;
    }

    Result execute(String token, String actionType, JsonNode action) throws Exception {
        JsonNode claims = axiom.introspect(token);
        if (!claims.path("active").asBoolean()) return new Result(null, Refusal.INACTIVE_TOKEN);
        JsonNode aud = claims.path("aud");
        String tokenAudience = aud.isArray() ? aud.path(0).asText() : aud.asText();
        if (!audience.equals(tokenAudience)) return new Result(null, Refusal.WRONG_AUDIENCE);
        if (!"approved_action".equals(claims.path("token_use").asText())) {
            return new Result(null, Refusal.NOT_AN_APPROVED_ACTION);
        }
        String digest = ActionCanonicalizer.canonicalize(actionType, audience, action).digest();
        if (!digest.equals(claims.path("action_digest").asText()) || !actionType.equals(claims.path("action_type").asText())) {
            return new Result(null, Refusal.DIGEST_MISMATCH);
        }
        String approvalId = claims.path("approval_id").asText();
        Outcome outcome = executions.computeIfAbsent(approvalId, id -> {
            effects.incrementAndGet();
            return new Outcome(UUID.randomUUID().toString(), id, digest);
        });
        if (!outcome.digest().equals(digest)) return new Result(null, Refusal.DIGEST_MISMATCH);
        return new Result(outcome, null);
    }
}
