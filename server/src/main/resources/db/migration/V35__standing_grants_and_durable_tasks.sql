-- Phase 3.3-3.5: standing offline authority, durable tasks bound to current authority, and verified task callbacks.
-- Grants, tokens, renewal handles, tasks and business records stay distinct: tokens are never stored, a renewal handle
-- is stored only as a keyed digest (current and immediately previous, for reuse detection), and tasks reference the
-- governing authority by id and version.
CREATE TABLE standing_grants (
    id                       UUID PRIMARY KEY,
    tenant_id                TEXT NOT NULL REFERENCES tenants(id),
    owner_principal_id       TEXT NOT NULL,
    owner_application_id     UUID NOT NULL,
    agent_workload_id        UUID NOT NULL REFERENCES agent_workload_identities(id),
    route_id                 UUID NOT NULL REFERENCES agent_exchange_routes(id),
    audience                 TEXT NOT NULL,
    scopes                   JSONB NOT NULL,
    purpose                  TEXT NOT NULL,
    approved_at              TIMESTAMPTZ NOT NULL,
    approved_auth_time       TIMESTAMPTZ NOT NULL,
    expires_at               TIMESTAMPTZ NOT NULL,
    status                   TEXT NOT NULL CHECK (status IN ('APPROVED', 'ACTIVE', 'REVOKED')),
    version                  BIGINT NOT NULL DEFAULT 1 CHECK (version >= 1),
    handle_digest            VARCHAR(64),
    previous_handle_digest   VARCHAR(64),
    handle_generation        BIGINT NOT NULL DEFAULT 0,
    claimed_at               TIMESTAMPTZ,
    last_renewed_at          TIMESTAMPTZ,
    revoked_at               TIMESTAMPTZ,
    revocation_reason        TEXT,
    created_at               TIMESTAMPTZ NOT NULL,
    CONSTRAINT standing_grant_window CHECK (expires_at > approved_at),
    CONSTRAINT standing_grant_revoked CHECK ((status = 'REVOKED') = (revoked_at IS NOT NULL)),
    CONSTRAINT standing_grant_claimed CHECK ((status = 'APPROVED') = (claimed_at IS NULL) OR status = 'REVOKED')
);
CREATE INDEX idx_standing_grants_owner ON standing_grants (tenant_id, owner_principal_id, status);
CREATE INDEX idx_standing_grants_workload ON standing_grants (tenant_id, agent_workload_id, status);

CREATE TABLE durable_tasks (
    id                   UUID PRIMARY KEY,
    tenant_id            TEXT NOT NULL REFERENCES tenants(id),
    agent_workload_id    UUID NOT NULL REFERENCES agent_workload_identities(id),
    owner_subject        TEXT NOT NULL,
    authority_type       TEXT NOT NULL CHECK (authority_type IN ('STANDING_GRANT', 'INVOCATION_CONTEXT')),
    authority_id         UUID NOT NULL,
    authority_version    BIGINT NOT NULL,
    task_ref             TEXT,
    callback_provider    TEXT,
    status               TEXT NOT NULL CHECK (status IN ('ACTIVE', 'CANCELLED', 'COMPLETED')),
    version              BIGINT NOT NULL DEFAULT 1,
    resume_count         INT NOT NULL DEFAULT 0,
    callback_count       INT NOT NULL DEFAULT 0,
    last_resumed_at      TIMESTAMPTZ,
    last_callback_at     TIMESTAMPTZ,
    ended_at             TIMESTAMPTZ,
    end_reason           TEXT,
    created_at           TIMESTAMPTZ NOT NULL,
    CONSTRAINT durable_task_ended CHECK ((status = 'ACTIVE') = (ended_at IS NULL))
);
CREATE UNIQUE INDEX uq_durable_tasks_ref ON durable_tasks (tenant_id, agent_workload_id, task_ref)
    WHERE task_ref IS NOT NULL;
CREATE INDEX idx_durable_tasks_authority ON durable_tasks (tenant_id, authority_type, authority_id);

-- One row per accepted callback; (provider, nonce) is unique per tenant, so a replay can never be accepted twice.
CREATE TABLE task_callbacks (
    id            UUID PRIMARY KEY,
    tenant_id     TEXT NOT NULL REFERENCES tenants(id),
    task_id       UUID NOT NULL REFERENCES durable_tasks(id),
    provider      TEXT NOT NULL,
    nonce         TEXT NOT NULL,
    event_type    TEXT NOT NULL,
    issued_at     TIMESTAMPTZ NOT NULL,
    body_digest   VARCHAR(64) NOT NULL,
    received_at   TIMESTAMPTZ NOT NULL
);
CREATE UNIQUE INDEX uq_task_callbacks_nonce ON task_callbacks (tenant_id, provider, nonce);
