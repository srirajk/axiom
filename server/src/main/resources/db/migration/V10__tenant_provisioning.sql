-- ============================================================
-- V10__tenant_provisioning.sql — Axiom Story B4 (tenant provisioning pipeline)
-- ============================================================
-- Two structural tables. `ddl-auto: validate` in prod means Hibernate creates NOTHING;
-- these definitions MUST match the JPA entities
--   com.openwolf.iam.tenancy.ProvisioningOperation  → tenant_provisioning_operations
--   com.openwolf.iam.tenancy.ActiveTenant           → active_tenants
-- No demo DATA lives here (that is the Python seeder's job) — this is schema only.

-- The idempotency-keyed provisioning/deprovisioning ledger. One row per run; the unique
-- idempotency key makes a retry load the same row and reconcile instead of forking a second run.
CREATE TABLE IF NOT EXISTS tenant_provisioning_operations (
    id                UUID PRIMARY KEY,
    idempotency_key   TEXT NOT NULL UNIQUE,
    tenant_id         TEXT NOT NULL,
    tenant_name       TEXT,
    slug              TEXT,
    kind              TEXT NOT NULL,          -- PROVISION | DEPROVISION
    status            TEXT NOT NULL,          -- PENDING | ACTIVE | FAILED | DEACTIVATED
    policy_version    TEXT,                   -- content-addressed bootstrap bundle version
    staged_artifacts  TEXT DEFAULT '',        -- comma-joined POLICY,REDIS,AUDIT
    last_error        TEXT,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_provisioning_ops_tenant
    ON tenant_provisioning_operations (tenant_id, created_at DESC);

-- The active directory: membership means a tenant is fully provisioned and VISIBLE. Written only by
-- the activation compare-and-set (last step of a provision) and removed FIRST on deprovision. The
-- gateway's A2 provisioned-tenant snapshot is a read replica of this set.
CREATE TABLE IF NOT EXISTS active_tenants (
    tenant_id         TEXT PRIMARY KEY,
    policy_version    TEXT NOT NULL,
    directory_version BIGINT NOT NULL,
    activated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
