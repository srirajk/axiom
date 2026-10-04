package com.openwolf.iam.authority.task;

import com.openwolf.iam.service.AuditService;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.HexFormat;
import java.util.Map;
import java.util.UUID;

/**
 * Phase 3.5 callback intake. A callback is accepted only when the configured verifier authenticates it for this
 * tenant, task, Axiom callback audience, timestamp, nonce, event and body; the task is ACTIVE and declared this
 * provider; the timestamp is fresh; and the (provider, nonce) pair has never been accepted. An accepted callback is
 * recorded and nothing else: it never grants authority or resumes work — resume always re-checks authority.
 */
@Service
public class TaskCallbackService {
    public enum Result { ACCEPTED }

    /** Refusal without detail for the caller; {@code status} is the HTTP status to return. */
    public static final class Refused extends RuntimeException {
        private final int status;

        Refused(int status, String reason) {
            super(reason, null, false, false);
            this.status = status;
        }

        public int status() { return status; }
    }

    private final DurableTaskRepository tasks;
    private final TaskCallbackVerifier verifier;
    private final JdbcTemplate jdbc;
    private final AuditService audit;
    private final Clock clock = Clock.systemUTC();
    private final Duration maxAge;

    public TaskCallbackService(DurableTaskRepository tasks, TaskCallbackVerifier verifier, JdbcTemplate jdbc,
                               AuditService audit,
                               @Value("${iam.task-callbacks.max-age:PT5M}") Duration maxAge) {
        if (maxAge.isNegative() || maxAge.isZero() || maxAge.compareTo(Duration.ofMinutes(15)) > 0) {
            throw new IllegalArgumentException("callback freshness window must be between one second and 15 minutes");
        }
        this.tasks = tasks; this.verifier = verifier; this.jdbc = jdbc; this.audit = audit; this.maxAge = maxAge;
    }

    /** The audience a callback must be signed for: this tenant's Axiom task-callback endpoint. */
    public static String audience(String tenantId) { return "axiom:task-callback:" + tenantId; }

    @Transactional
    public Result accept(String tenantId, UUID taskId, String provider, long issuedAtEpoch, String nonce,
                         String eventType, byte[] body, String signature) {
        Instant now = clock.instant();
        if (signature == null || signature.isBlank()) throw new Refused(401, "unsigned callback");
        if (provider == null || nonce == null || eventType == null
                || !provider.matches("[A-Za-z0-9][A-Za-z0-9._:-]{0,127}") || !nonce.matches("[A-Za-z0-9._:-]{16,128}")
                || !eventType.matches("[a-z][a-z0-9._-]{0,63}")) {
            throw new Refused(400, "malformed callback");
        }
        Instant issuedAt = Instant.ofEpochSecond(issuedAtEpoch);
        if (issuedAt.isBefore(now.minus(maxAge)) || issuedAt.isAfter(now.plusSeconds(30))) {
            throw new Refused(401, "stale or future callback");
        }
        String bodyDigest = sha256(body);
        try {
            verifier.verify(new TaskCallbackVerifier.CallbackClaim(tenantId, provider, taskId, audience(tenantId),
                    issuedAt, nonce, eventType, bodyDigest), signature);
        } catch (RuntimeException rejected) {
            throw new Refused(401, "callback not authenticated");
        }
        DurableTask task = tasks.lock(taskId, tenantId).orElseThrow(() -> new Refused(404, "unknown task"));
        if (!provider.equals(task.getCallbackProvider())) throw new Refused(403, "provider not bound to task");
        if (task.getStatus() != DurableTask.Status.ACTIVE) throw new Refused(409, "task is not active");
        // ON CONFLICT DO NOTHING reports 0 rows for a (tenant, provider, nonce) already accepted: a replay.
        int inserted = jdbc.update("INSERT INTO task_callbacks (id, tenant_id, task_id, provider, nonce, event_type, "
                + "issued_at, body_digest, received_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT DO NOTHING",
                UUID.randomUUID(), tenantId, taskId, provider, nonce, eventType,
                java.sql.Timestamp.from(issuedAt), bodyDigest, java.sql.Timestamp.from(now));
        if (inserted != 1) throw new Refused(409, "replayed callback");
        task.callback(now);
        audit.logRequired(tenantId, provider, "TASK_CALLBACK_ACCEPTED", "durable_task", taskId.toString(), null,
                Map.of("provider", provider, "event_type", eventType, "issued_at", issuedAt.toString(),
                        "body_digest", bodyDigest), taskId.toString());
        return Result.ACCEPTED;
    }

    static String sha256(byte[] body) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(body == null ? new byte[0] : body));
        } catch (Exception e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }

    static byte[] utf8(String value) { return value.getBytes(StandardCharsets.UTF_8); }
}
