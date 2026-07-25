package com.openwolf.iam.policystudio.lifecycle;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

import java.time.Instant;
import java.util.UUID;

/**
 * The durable, idempotency-keyed receipt for one promotion or rollback (Axiom Story C5). One row per
 * promotion intent; the unique idempotency key makes a lost-response retry load the SAME row and return
 * the same receipt instead of promoting twice (C5.3, onboarding §10). Both a forward promotion and a
 * rollback are the same kind of authorized CAS — a rollback simply promotes a previously certified
 * bundle — so both live in this one ledger (§11: rollback is a new authorized promotion, not a reversal).
 *
 * <p>{@code ddl-auto: validate} — columns MUST match {@code V11__policy_lifecycle.sql}.
 */
@Entity
@Table(name = "bundle_promotions")
public class PromotionRecord {

    public enum Kind { PROMOTION, ROLLBACK }

    public enum Status { PROMOTED, FAILED }

    @Id
    @Column(name = "id")
    private UUID id;

    @Column(name = "idempotency_key", nullable = false, unique = true)
    private String idempotencyKey;

    @Column(name = "tenant_id", nullable = false)
    private String tenantId;

    @Column(name = "from_bundle_id")
    private String fromBundleId;

    @Column(name = "to_bundle_id", nullable = false)
    private String toBundleId;

    @Column(name = "consequence_review_hash", nullable = false)
    private String consequenceReviewHash;

    @Column(name = "approver_id", nullable = false)
    private String approverId;

    @Enumerated(EnumType.STRING)
    @Column(name = "kind", nullable = false)
    private Kind kind;

    @Enumerated(EnumType.STRING)
    @Column(name = "status", nullable = false)
    private Status status;

    @Column(name = "directory_version")
    private Long directoryVersion;

    @Column(name = "last_error")
    private String lastError;

    @Column(name = "created_at", nullable = false)
    private Instant createdAt;

    protected PromotionRecord() {}

    public PromotionRecord(String idempotencyKey, String tenantId, String fromBundleId, String toBundleId,
                           String consequenceReviewHash, String approverId, Kind kind) {
        this.id = UUID.randomUUID();
        this.idempotencyKey = idempotencyKey;
        this.tenantId = tenantId;
        this.fromBundleId = fromBundleId;
        this.toBundleId = toBundleId;
        this.consequenceReviewHash = consequenceReviewHash;
        this.approverId = approverId;
        this.kind = kind;
        this.status = Status.FAILED; // not visible until the CAS succeeds
        this.createdAt = Instant.now();
    }

    public void markPromoted(long directoryVersion) {
        this.status = Status.PROMOTED;
        this.directoryVersion = directoryVersion;
        this.lastError = null;
    }

    public void markFailed(String error) {
        this.status = Status.FAILED;
        this.lastError = error;
    }

    public String getId() { return id.toString(); }
    public String getIdempotencyKey() { return idempotencyKey; }
    public String getTenantId() { return tenantId; }
    public String getFromBundleId() { return fromBundleId; }
    public String getToBundleId() { return toBundleId; }
    public String getConsequenceReviewHash() { return consequenceReviewHash; }
    public String getApproverId() { return approverId; }
    public Kind getKind() { return kind; }
    public Status getStatus() { return status; }
    public Long getDirectoryVersion() { return directoryVersion; }
    public String getLastError() { return lastError; }
    public Instant getCreatedAt() { return createdAt; }
}
