package com.openwolf.iam.policystudio.lifecycle;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

import java.time.Instant;

/**
 * The durable, immutable record for one promoted/certified policy bundle (Axiom Story C5): it maps the
 * content-addressed {@code bundleId} to its Git commit and retains the canonical bytes + certifying test
 * metadata. This is the examiner's join target — a decision's active policy version resolves here, then
 * to the Git commit and the approvals/tests that certified it (C5.6). Records are append-only and never
 * updated; a bundle "changing" is always a NEW bundle with a NEW id.
 *
 * <p>{@code ddl-auto: validate} — columns MUST match {@code V11__policy_lifecycle.sql}.
 */
@Entity
@Table(name = "policy_bundles")
public class PolicyBundleRecord {

    @Id
    @Column(name = "bundle_id")
    private String bundleId;

    @Column(name = "tenant_id", nullable = false)
    private String tenantId;

    @Column(name = "git_commit")
    private String gitCommit;

    @Column(name = "fixture_set_hash", nullable = false)
    private String fixtureSetHash;

    @Column(name = "test_count", nullable = false)
    private int testCount;

    @Column(name = "test_oracle")
    private String testOracle;

    @Column(name = "pdp_source_id", nullable = false)
    private String pdpSourceId;

    @Column(name = "canonical_content", nullable = false, columnDefinition = "text")
    private String canonicalContent;

    @Column(name = "created_at", nullable = false)
    private Instant createdAt;

    protected PolicyBundleRecord() {}

    public PolicyBundleRecord(PolicyBundle bundle, String gitCommit) {
        this.bundleId = bundle.bundleId();
        this.tenantId = bundle.tenantId();
        this.gitCommit = gitCommit;
        this.fixtureSetHash = bundle.testMetadata().fixtureSetHash();
        this.testCount = bundle.testMetadata().testCount();
        this.testOracle = bundle.testMetadata().oracle();
        this.pdpSourceId = bundle.testMetadata().pdpSourceId();
        this.canonicalContent = bundle.canonicalContent();
        this.createdAt = Instant.now();
    }

    public String getBundleId() { return bundleId; }
    public String getTenantId() { return tenantId; }
    public String getGitCommit() { return gitCommit; }
    public String getFixtureSetHash() { return fixtureSetHash; }
    public int getTestCount() { return testCount; }
    public String getTestOracle() { return testOracle; }
    public String getPdpSourceId() { return pdpSourceId; }
    public String getCanonicalContent() { return canonicalContent; }
    public Instant getCreatedAt() { return createdAt; }

    public BundleTestMetadata testMetadata() {
        return new BundleTestMetadata(fixtureSetHash, testCount, testOracle, pdpSourceId);
    }

    /** Recompute the content-addressed id from the retained canonical bytes — the durable integrity check. */
    public boolean contentMatchesId(BundleCanonicalizer canon) {
        return bundleId.equals(canon.bundleId(canonicalContent));
    }
}
