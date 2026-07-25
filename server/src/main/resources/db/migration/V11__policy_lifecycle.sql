-- ============================================================
-- V11__policy_lifecycle.sql — Axiom Story C5 (immutable versioned bundle + promotion + examiner)
-- ============================================================
-- Append-only, immutable records. `ddl-auto: validate` in prod means Hibernate creates NOTHING;
-- these definitions MUST match the JPA entities under
--   com.openwolf.iam.policystudio.lifecycle
--     PolicyBundleRecord      → policy_bundles
--     PromotionRecord         → bundle_promotions
--     ApplicationAuditEntry   → application_audit_index
--     CerbosDecisionEntry     → cerbos_decision_log
--     ApprovalRecordEntity    → consequence_approvals
-- No demo DATA lives here (that is the Python seeder's job) — this is schema only. V10 is B4's
-- provisioning ledger; C5 is additive and never alters V10.

-- The immutable, content-addressed policy-bundle record: bundleId → Git commit + canonical bytes +
-- certifying test metadata. Append-only; a bundle "changing" is a NEW row with a NEW id. Old versions
-- remain for the evidence-retention period (rollback is a new promotion, never a delete).
CREATE TABLE IF NOT EXISTS policy_bundles (
    bundle_id          TEXT PRIMARY KEY,        -- b_<sha256 of canonical full-bundle bytes>
    tenant_id          TEXT NOT NULL,
    git_commit         TEXT,                    -- the commit the immutable record maps the bundle to
    fixture_set_hash   TEXT NOT NULL,           -- certifying matrix (C4/C3)
    test_count         INTEGER NOT NULL,
    test_oracle        TEXT,                    -- independent test-gen oracle (C3)
    pdp_source_id      TEXT NOT NULL,           -- e.g. cerbos:0.53.0
    canonical_content  TEXT NOT NULL,           -- exact canonical bytes the id derives from (re-hashable)
    created_at         TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_policy_bundles_tenant
    ON policy_bundles (tenant_id, created_at DESC);

-- The idempotency-keyed promotion/rollback ledger. One row per promotion intent; the unique
-- idempotency key makes a lost-response retry return the same receipt instead of promoting twice.
CREATE TABLE IF NOT EXISTS bundle_promotions (
    id                       UUID PRIMARY KEY,
    idempotency_key          TEXT NOT NULL UNIQUE,
    tenant_id                TEXT NOT NULL,
    from_bundle_id           TEXT,               -- reviewed OLD id the CAS required (null = first)
    to_bundle_id             TEXT NOT NULL,      -- candidate id activated
    consequence_review_hash  TEXT NOT NULL,      -- the C4 review hash the approval signed
    approver_id              TEXT NOT NULL,
    kind                     TEXT NOT NULL,      -- PROMOTION | ROLLBACK
    status                   TEXT NOT NULL,      -- PROMOTED | FAILED
    directory_version        BIGINT,             -- published directory snapshot version on success
    last_error               TEXT,
    created_at               TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_bundle_promotions_tenant
    ON bundle_promotions (tenant_id, created_at DESC);

-- The application-side audit index: the examiner's entry point. Mirrors the serving audit record's
-- promoted join keys (cerbosCallId + activePolicyVersion) so a recorded decision can be walked back to
-- the decision log, the bundle, the Git commit, and the approvals/tests.
CREATE TABLE IF NOT EXISTS application_audit_index (
    id                    UUID PRIMARY KEY,
    transaction_id        TEXT NOT NULL,
    tenant_id             TEXT NOT NULL,
    cerbos_call_id        TEXT NOT NULL,
    active_policy_version TEXT NOT NULL,         -- the immutable bundle id the request ran under (A2)
    occurred_at           TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_app_audit_call     ON application_audit_index (cerbos_call_id);
CREATE INDEX IF NOT EXISTS idx_app_audit_txn      ON application_audit_index (transaction_id, occurred_at);

-- The durable Cerbos decision log, keyed by cerbosCallId. Carries the activePolicyVersion the PDP
-- evaluated under; the examiner asserts it equals the application audit's version (no split request).
CREATE TABLE IF NOT EXISTS cerbos_decision_log (
    cerbos_call_id        TEXT PRIMARY KEY,
    tenant_id             TEXT NOT NULL,
    active_policy_version TEXT NOT NULL,
    decision              TEXT NOT NULL,         -- ALLOW | DENY
    resource_kind         TEXT,
    action                TEXT,
    occurred_at           TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- The signed consequence approvals (C4) persisted for the examiner's approvals/tests hop, keyed so a
-- promoted bundle joins to the approval that authorized it (candidate bundle id) for HMAC re-verification.
CREATE TABLE IF NOT EXISTS consequence_approvals (
    id                       UUID PRIMARY KEY,
    tenant_id                TEXT NOT NULL,
    current_bundle_id        TEXT NOT NULL,
    candidate_bundle_id      TEXT NOT NULL,
    fixture_set_hash         TEXT NOT NULL,
    consequence_review_hash  TEXT NOT NULL,
    over_permission_alarm    BOOLEAN NOT NULL,
    approver_id              TEXT NOT NULL,
    approver_roles           TEXT NOT NULL,
    decision                 TEXT NOT NULL,      -- APPROVE | REJECT
    signature                TEXT NOT NULL,      -- HMAC-SHA256 over the approval payload
    signed_at                TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_approvals_candidate
    ON consequence_approvals (candidate_bundle_id);
