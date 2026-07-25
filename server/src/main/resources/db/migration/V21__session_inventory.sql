-- AXP-5: durable tenant-scoped OAuth session inventory and revocation.
CREATE TABLE iam_sessions (
    id             UUID PRIMARY KEY,
    tenant_id      TEXT NOT NULL REFERENCES tenants(id),
    principal_id   TEXT NOT NULL,
    application_id UUID,
    client_id      VARCHAR(100) NOT NULL,
    issued_at      TIMESTAMPTZ NOT NULL,
    last_seen_at   TIMESTAMPTZ NOT NULL,
    expires_at     TIMESTAMPTZ NOT NULL,
    status         TEXT NOT NULL CHECK (status IN ('ACTIVE', 'REVOKED', 'EXPIRED')),
    revision       BIGINT NOT NULL DEFAULT 1,
    CONSTRAINT uq_iam_sessions_identity UNIQUE (tenant_id, id)
);

CREATE INDEX idx_iam_sessions_tenant_last_seen ON iam_sessions (tenant_id, last_seen_at DESC);
CREATE INDEX idx_iam_sessions_tenant_principal ON iam_sessions (tenant_id, principal_id, status);
CREATE INDEX idx_iam_sessions_tenant_client ON iam_sessions (tenant_id, client_id, status);
