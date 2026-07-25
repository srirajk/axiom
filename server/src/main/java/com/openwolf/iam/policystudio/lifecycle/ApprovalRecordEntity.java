package com.openwolf.iam.policystudio.lifecycle;

import com.openwolf.iam.policystudio.ApprovalDecision;
import com.openwolf.iam.policystudio.ConsequenceApprovalRecord;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

import java.time.Instant;
import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.Set;
import java.util.UUID;

/**
 * The durable persistence of a C4 {@link ConsequenceApprovalRecord} (Axiom Story C5). C4 signs an
 * approval over the exact {@code consequenceReviewHash}; C5 stores it, keyed so the examiner can join a
 * promoted bundle back to the approval that authorized it (candidate bundle id) and re-verify the HMAC
 * signature over the exact machine consequences the human approved. Immutable/append-only.
 *
 * <p>{@code ddl-auto: validate} — columns MUST match {@code V11__policy_lifecycle.sql}.
 */
@Entity
@Table(name = "consequence_approvals")
public class ApprovalRecordEntity {

    @Id
    @Column(name = "id")
    private UUID id;

    @Column(name = "tenant_id", nullable = false)
    private String tenantId;

    @Column(name = "current_bundle_id", nullable = false)
    private String currentBundleId;

    @Column(name = "candidate_bundle_id", nullable = false)
    private String candidateBundleId;

    @Column(name = "fixture_set_hash", nullable = false)
    private String fixtureSetHash;

    @Column(name = "consequence_review_hash", nullable = false)
    private String consequenceReviewHash;

    @Column(name = "over_permission_alarm", nullable = false)
    private boolean overPermissionAlarm;

    @Column(name = "approver_id", nullable = false)
    private String approverId;

    @Column(name = "approver_roles", nullable = false)
    private String approverRoles;

    @Column(name = "decision", nullable = false)
    private String decision;

    @Column(name = "signature", nullable = false)
    private String signature;

    @Column(name = "signed_at", nullable = false)
    private Instant signedAt;

    protected ApprovalRecordEntity() {}

    public ApprovalRecordEntity(ConsequenceApprovalRecord record) {
        this.id = UUID.randomUUID();
        this.tenantId = record.tenantId();
        this.currentBundleId = record.currentBundleId();
        this.candidateBundleId = record.candidateBundleId();
        this.fixtureSetHash = record.fixtureSetHash();
        this.consequenceReviewHash = record.consequenceReviewHash();
        this.overPermissionAlarm = record.overPermissionAlarm();
        this.approverId = record.approverId();
        this.approverRoles = String.join(",", new java.util.TreeSet<>(record.approverRoles()));
        this.decision = record.decision().name();
        this.signature = record.signature();
        this.signedAt = record.signedAt();
    }

    /** Reconstruct the exact signed record so the examiner can re-verify the HMAC signature. */
    public ConsequenceApprovalRecord toRecord() {
        Set<String> roles = approverRoles.isBlank()
                ? Set.of()
                : new LinkedHashSet<>(Arrays.asList(approverRoles.split(",")));
        return new ConsequenceApprovalRecord(tenantId, currentBundleId, candidateBundleId, fixtureSetHash,
                consequenceReviewHash, overPermissionAlarm, approverId, roles,
                ApprovalDecision.valueOf(decision), signature, signedAt);
    }

    public String getId() { return id.toString(); }
    public String getTenantId() { return tenantId; }
    public String getCurrentBundleId() { return currentBundleId; }
    public String getCandidateBundleId() { return candidateBundleId; }
    public String getConsequenceReviewHash() { return consequenceReviewHash; }
    public String getApproverId() { return approverId; }
    public String getDecision() { return decision; }
    public String getSignature() { return signature; }
    public Instant getSignedAt() { return signedAt; }
}
