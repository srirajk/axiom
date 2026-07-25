-- AXP-2: application access is distinct from tenant-wide Axiom administration.
CREATE TABLE tenant_application_memberships (
    id                   UUID PRIMARY KEY,
    application_id       UUID NOT NULL REFERENCES tenant_applications(id) ON DELETE RESTRICT,
    principal_id         TEXT NOT NULL REFERENCES principals(id) ON DELETE RESTRICT,
    status               TEXT NOT NULL CHECK (status IN ('ACTIVE', 'DISABLED')),
    attributes           JSONB NOT NULL DEFAULT '{}',
    assignment_source    TEXT NOT NULL,
    assigned_by          TEXT NOT NULL,
    entitlement_revision BIGINT NOT NULL DEFAULT 1,
    created_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (application_id, principal_id)
);

CREATE TABLE tenant_application_roles (
    id             UUID PRIMARY KEY,
    application_id UUID NOT NULL REFERENCES tenant_applications(id) ON DELETE RESTRICT,
    role_key       TEXT NOT NULL,
    display_name   TEXT NOT NULL,
    description    TEXT,
    permissions    JSONB NOT NULL DEFAULT '[]',
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (application_id, role_key)
);

CREATE TABLE tenant_application_role_assignments (
    id                UUID PRIMARY KEY,
    membership_id     UUID NOT NULL REFERENCES tenant_application_memberships(id) ON DELETE RESTRICT,
    application_role_id UUID NOT NULL REFERENCES tenant_application_roles(id) ON DELETE RESTRICT,
    assignment_source TEXT NOT NULL,
    assigned_by       TEXT NOT NULL,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    revoked_at        TIMESTAMPTZ,
    UNIQUE (membership_id, application_role_id)
);

CREATE INDEX idx_application_memberships_application ON tenant_application_memberships (application_id, status);
CREATE INDEX idx_application_memberships_principal ON tenant_application_memberships (principal_id, status);
CREATE INDEX idx_application_roles_application ON tenant_application_roles (application_id);
CREATE INDEX idx_application_role_assignments_membership ON tenant_application_role_assignments (membership_id, revoked_at);
