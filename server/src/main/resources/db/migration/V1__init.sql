-- ============================================================
-- V1__init.sql — Axiom identity and platform-policy schema
-- ============================================================
-- AXM-107: this migration intentionally creates schema only. No tenant, user,
-- role, group, relationship/book, policy bundle, or demo/default identity is seeded.

CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE IF NOT EXISTS tenants (
    id                    TEXT PRIMARY KEY,
    name                  TEXT NOT NULL,
    slug                  TEXT NOT NULL UNIQUE,
    classification_schema JSONB NOT NULL DEFAULT '[]',
    created_at            TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS principals (
    id            TEXT PRIMARY KEY,
    tenant_id     TEXT NOT NULL REFERENCES tenants(id),
    username      TEXT NOT NULL UNIQUE,
    email         TEXT,
    password_hash TEXT NOT NULL,
    is_active     BOOLEAN NOT NULL DEFAULT TRUE,
    attributes    JSONB NOT NULL DEFAULT '{}',
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, id)
);

CREATE TABLE IF NOT EXISTS roles (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id   TEXT NOT NULL REFERENCES tenants(id),
    name        TEXT NOT NULL,
    permissions JSONB NOT NULL DEFAULT '[]',
    description TEXT,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, name),
    UNIQUE (tenant_id, id)
);

CREATE TABLE IF NOT EXISTS principal_roles (
    principal_id TEXT NOT NULL,
    role_id      UUID NOT NULL,
    tenant_id    TEXT NOT NULL,
    PRIMARY KEY (principal_id, role_id),
    FOREIGN KEY (tenant_id, principal_id) REFERENCES principals(tenant_id, id) ON DELETE CASCADE,
    FOREIGN KEY (tenant_id, role_id) REFERENCES roles(tenant_id, id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS groups (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id   TEXT NOT NULL REFERENCES tenants(id),
    name        TEXT NOT NULL,
    domain_id   TEXT,
    description TEXT,
    metadata    JSONB NOT NULL DEFAULT '{}',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, name)
);

CREATE TABLE IF NOT EXISTS group_members (
    group_id     UUID NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    principal_id TEXT NOT NULL REFERENCES principals(id) ON DELETE CASCADE,
    PRIMARY KEY (group_id, principal_id)
);

CREATE TABLE IF NOT EXISTS policies (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id     TEXT NOT NULL,
    name          TEXT NOT NULL,
    resource_type TEXT,
    content       TEXT NOT NULL,
    status        TEXT NOT NULL DEFAULT 'draft' CHECK (status IN ('draft', 'approved', 'deployed')),
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, name)
);

CREATE TABLE IF NOT EXISTS audit_log (
    id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id      TEXT NOT NULL,
    actor_id       TEXT,
    client_id      TEXT NOT NULL DEFAULT 'system',
    action         TEXT NOT NULL,
    resource_type  TEXT,
    resource_id    TEXT,
    before_state   JSONB,
    after_state    JSONB,
    source_ip      TEXT,
    correlation_id TEXT,
    occurred_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_principals_tenant_id      ON principals (tenant_id);
CREATE INDEX IF NOT EXISTS idx_principals_username        ON principals (username);
CREATE INDEX IF NOT EXISTS idx_roles_tenant_id            ON roles (tenant_id);
CREATE INDEX IF NOT EXISTS idx_principal_roles_tenant     ON principal_roles (tenant_id);
CREATE INDEX IF NOT EXISTS idx_groups_tenant_id           ON groups (tenant_id);
CREATE INDEX IF NOT EXISTS idx_groups_domain_id           ON groups (domain_id);
CREATE INDEX IF NOT EXISTS idx_group_members_principal_id ON group_members (principal_id);
CREATE INDEX IF NOT EXISTS idx_policies_tenant_id         ON policies (tenant_id);
CREATE INDEX IF NOT EXISTS idx_audit_log_tenant_occurred  ON audit_log (tenant_id, occurred_at DESC);
