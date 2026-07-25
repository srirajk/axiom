-- AXP-1: tenant-owned application identity is distinct from Spring Authorization Server's
-- protocol registry.  The latter remains the source of OAuth mechanics; these tables are
-- the tenant/application authority used to decide whether a client may mint a token.
CREATE TABLE tenant_applications (
    id           UUID PRIMARY KEY,
    tenant_id    TEXT NOT NULL REFERENCES tenants(id),
    application_key TEXT NOT NULL,
    display_name TEXT NOT NULL,
    description  TEXT,
    audience     TEXT NOT NULL,
    status       TEXT NOT NULL CHECK (status IN ('ACTIVE', 'DISABLED')),
    revision     BIGINT NOT NULL DEFAULT 1,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, application_key),
    UNIQUE (tenant_id, audience)
);

CREATE TABLE tenant_application_clients (
    id             UUID PRIMARY KEY,
    application_id UUID NOT NULL REFERENCES tenant_applications(id) ON DELETE RESTRICT,
    client_id      VARCHAR(100) NOT NULL REFERENCES oauth2_registered_client(client_id) ON DELETE RESTRICT,
    client_type    TEXT NOT NULL CHECK (client_type IN ('PUBLIC_BROWSER', 'CONFIDENTIAL_SERVICE')),
    status         TEXT NOT NULL CHECK (status IN ('ACTIVE', 'DISABLED')),
    allowed_scopes JSONB NOT NULL DEFAULT '[]',
    revision       BIGINT NOT NULL DEFAULT 1,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (client_id)
);

CREATE INDEX idx_tenant_applications_tenant ON tenant_applications (tenant_id, status);
CREATE INDEX idx_tenant_application_clients_application ON tenant_application_clients (application_id, status);
