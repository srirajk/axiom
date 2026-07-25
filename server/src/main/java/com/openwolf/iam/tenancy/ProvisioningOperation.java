package com.openwolf.iam.tenancy;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

import java.time.Instant;
import java.util.LinkedHashSet;
import java.util.Objects;
import java.util.Set;
import java.util.TreeSet;
import java.util.UUID;

/**
 * The persisted, idempotency-keyed ledger row for one tenant provisioning (or deprovisioning) run
 * (Axiom Story B4 — the provisioning-operation entity). Provisioning stages three artifacts (policy
 * bootstrap, Redis namespace, audit partition) and only then flips the active
 * directory; a crash or injected failure leaves this row in a non-{@code ACTIVE} state and the
 * tenant absent from the directory, so the tenant is <b>fully unusable</b> until a retry with the
 * same idempotency key reconciles it. The row is the durable evidence of "how far did we get" and
 * the key that makes a retry safe (never a second, conflicting run).
 *
 * <p>{@code ddl-auto: validate} — every column here MUST match {@code V10__tenant_provisioning.sql}.
 */
@Entity
@Table(name = "tenant_provisioning_operations")
public class ProvisioningOperation {

    /** The three AXM-1 artifacts a provision must stage before the directory flip. */
    public enum Artifact { POLICY, REDIS, AUDIT }

    /** Provision vs deprovision — the same ledger carries both so an examiner sees the whole life. */
    public enum Kind { PROVISION, DEPROVISION }

    /**
     * Terminal-ish lifecycle of a run. {@code PENDING} = staging under way (or stalled after a
     * failure); {@code ACTIVE} = all three verified and the directory CAS committed; {@code FAILED} =
     * a stage threw and the tenant is NOT in the directory; {@code DEACTIVATED} = deprovision
     * committed (directory revoked, non-audit artifacts cleaned, audit retained).
     */
    public enum Status { PENDING, ACTIVE, FAILED, DEACTIVATED }

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @Column(name = "idempotency_key", nullable = false, unique = true)
    private String idempotencyKey;

    @Column(name = "tenant_id", nullable = false)
    private String tenantId;

    @Column(name = "tenant_name")
    private String tenantName;

    @Column(name = "slug")
    private String slug;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private Kind kind;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private Status status;

    @Column(name = "policy_version")
    private String policyVersion;

    /** Comma-joined {@link Artifact} names already staged/verified in this run (idempotent set). */
    @Column(name = "staged_artifacts")
    private String stagedArtifacts = "";

    @Column(name = "last_error", columnDefinition = "text")
    private String lastError;

    @Column(name = "created_at", nullable = false)
    private Instant createdAt;

    @Column(name = "updated_at", nullable = false)
    private Instant updatedAt;

    protected ProvisioningOperation() {}

    public ProvisioningOperation(String idempotencyKey, String tenantId, String tenantName,
                                 String slug, Kind kind) {
        this.idempotencyKey = idempotencyKey;
        this.tenantId = tenantId;
        this.tenantName = tenantName;
        this.slug = slug;
        this.kind = kind;
        this.status = Status.PENDING;
        Instant now = Instant.now();
        this.createdAt = now;
        this.updatedAt = now;
    }

    public UUID getId() { return id; }
    public String getIdempotencyKey() { return idempotencyKey; }
    public String getTenantId() { return tenantId; }
    public String getTenantName() { return tenantName; }
    public String getSlug() { return slug; }
    public Kind getKind() { return kind; }
    public Status getStatus() { return status; }
    public String getPolicyVersion() { return policyVersion; }
    public String getLastError() { return lastError; }
    public Instant getCreatedAt() { return createdAt; }
    public Instant getUpdatedAt() { return updatedAt; }

    public void setStatus(Status status) { this.status = status; touch(); }
    public void setPolicyVersion(String policyVersion) { this.policyVersion = policyVersion; touch(); }

    public void setLastError(String lastError) {
        // Never let an over-long stack trace break the column; keep the head.
        this.lastError = lastError == null ? null
                : (lastError.length() > 4000 ? lastError.substring(0, 4000) : lastError);
        touch();
    }

    /** Mark an artifact staged. Idempotent — re-marking the same artifact is a no-op set-add. */
    public void markStaged(Artifact artifact) {
        Set<String> set = stagedArtifactSet();
        set.add(artifact.name());
        // Deterministic order so the stored string is stable across retries (evidence stability).
        this.stagedArtifacts = String.join(",", new TreeSet<>(set));
        touch();
    }

    public boolean isStaged(Artifact artifact) {
        return stagedArtifactSet().contains(artifact.name());
    }

    public Set<Artifact> stagedArtifacts() {
        Set<Artifact> out = new LinkedHashSet<>();
        for (String s : stagedArtifactSet()) {
            out.add(Artifact.valueOf(s));
        }
        return out;
    }

    private Set<String> stagedArtifactSet() {
        Set<String> set = new LinkedHashSet<>();
        if (stagedArtifacts != null && !stagedArtifacts.isBlank()) {
            for (String s : stagedArtifacts.split(",")) {
                if (!s.isBlank()) set.add(s.trim());
            }
        }
        return set;
    }

    private void touch() { this.updatedAt = Instant.now(); }

    @Override
    public boolean equals(Object o) {
        return o instanceof ProvisioningOperation op && Objects.equals(id, op.id);
    }

    @Override
    public int hashCode() {
        return Objects.hash(id);
    }
}
