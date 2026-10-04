-- Phase 3.10/3.12/3.15: generic, Axiom-owned identity lifecycle. No partner or hosted-provider profile is named here.
--   * Agent workloads gain SUSPENDED (reversible) and RETIRED (terminal) states and explicit team ownership with one
--     accountable principal. Every authority check already requires ACTIVE, so both states stop new authority.
--   * Access reviews are recorded per workload.
--   * Confidential-client secret rotation can keep the previous secret valid for a bounded, declared overlap.
--   * Workload federation binds an external (provider, issuer, subject) to exactly one workload; assertions are
--     single-use (issuer, jti).
ALTER TABLE agent_workload_identities DROP CONSTRAINT agent_workload_identities_status_check;
ALTER TABLE agent_workload_identities ADD CONSTRAINT agent_workload_identities_status_check
    CHECK (status IN ('ACTIVE', 'SUSPENDED', 'REVOKED', 'RETIRED'));
ALTER TABLE agent_workload_identities
    ADD COLUMN suspended_at TIMESTAMPTZ,
    ADD COLUMN suspension_reason TEXT,
    ADD COLUMN retired_at TIMESTAMPTZ,
    ADD COLUMN owner_team_id UUID REFERENCES groups(id) ON DELETE SET NULL,
    ADD COLUMN accountable_principal_id TEXT,
    ADD COLUMN ownership_assigned_at TIMESTAMPTZ,
    ADD COLUMN last_reviewed_at TIMESTAMPTZ;
ALTER TABLE agent_workload_identities ADD CONSTRAINT agent_workload_suspended
    CHECK ((status = 'SUSPENDED') = (suspended_at IS NOT NULL));
ALTER TABLE agent_workload_identities ADD CONSTRAINT agent_workload_retired
    CHECK ((status = 'RETIRED') = (retired_at IS NOT NULL));
CREATE INDEX idx_agent_workload_accountable ON agent_workload_identities (tenant_id, accountable_principal_id);

CREATE TABLE workload_access_reviews (
    id                  UUID PRIMARY KEY,
    tenant_id           TEXT NOT NULL REFERENCES tenants(id),
    agent_workload_id   UUID NOT NULL REFERENCES agent_workload_identities(id),
    reviewer            TEXT NOT NULL,
    decision            TEXT NOT NULL CHECK (decision IN ('KEEP', 'SUSPEND', 'RETIRE')),
    notes               TEXT,
    ownership_valid     BOOLEAN NOT NULL,
    reviewed_at         TIMESTAMPTZ NOT NULL
);
CREATE INDEX idx_workload_access_reviews ON workload_access_reviews (tenant_id, agent_workload_id, reviewed_at);

CREATE TABLE client_secret_overlaps (
    client_id             TEXT PRIMARY KEY,
    previous_secret_hash  TEXT NOT NULL,
    valid_until           TIMESTAMPTZ NOT NULL,
    rotated_at            TIMESTAMPTZ NOT NULL
);

CREATE TABLE workload_federation_bindings (
    id                  UUID PRIMARY KEY,
    tenant_id           TEXT NOT NULL REFERENCES tenants(id),
    agent_workload_id   UUID NOT NULL REFERENCES agent_workload_identities(id),
    provider_profile    TEXT NOT NULL CHECK (provider_profile ~ '^[a-z][a-z0-9._-]{1,63}$'),
    issuer              TEXT NOT NULL,
    subject             TEXT NOT NULL,
    status              TEXT NOT NULL CHECK (status IN ('ACTIVE', 'REVOKED')),
    created_at          TIMESTAMPTZ NOT NULL,
    revoked_at          TIMESTAMPTZ,
    CONSTRAINT workload_federation_revoked CHECK ((status = 'REVOKED') = (revoked_at IS NOT NULL))
);
-- One external identity maps to at most one active workload, anywhere.
CREATE UNIQUE INDEX uq_workload_federation_identity
    ON workload_federation_bindings (provider_profile, issuer, subject) WHERE status = 'ACTIVE';

CREATE TABLE workload_assertion_replays (
    provider_profile  TEXT NOT NULL,
    issuer            TEXT NOT NULL,
    jti               TEXT NOT NULL,
    expires_at        TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (provider_profile, issuer, jti)
);
