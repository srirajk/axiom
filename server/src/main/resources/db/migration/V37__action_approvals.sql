-- Phase 3.7-3.9/3.13: exact-action approvals. The approved operation is stored in canonical form with its SHA-256
-- digest; approval, initiator confirmation (step-up) and single-use consumption are status transitions of one row.
-- Business execution records belong to the receiver, not to Axiom.
CREATE TABLE action_approvals (
    id                        UUID PRIMARY KEY,
    tenant_id                 TEXT NOT NULL REFERENCES tenants(id),
    initiator_principal_id    TEXT NOT NULL,
    agent_workload_id         UUID NOT NULL REFERENCES agent_workload_identities(id),
    owner_application_id      UUID NOT NULL,
    route_id                  UUID NOT NULL REFERENCES agent_exchange_routes(id),
    receiver_audience         TEXT NOT NULL,
    scopes                    JSONB NOT NULL,
    action_type               TEXT NOT NULL CHECK (action_type ~ '^[a-z][a-z0-9._-]{1,63}$'),
    canonical_action          TEXT NOT NULL,
    action_digest             VARCHAR(64) NOT NULL,
    required_acr              JSONB NOT NULL,
    max_auth_age_seconds      INT NOT NULL CHECK (max_auth_age_seconds > 0),
    deadline                  TIMESTAMPTZ NOT NULL,
    status                    TEXT NOT NULL CHECK (status IN ('PENDING', 'APPROVED', 'CONFIRMED', 'CONSUMED',
                                                              'REJECTED', 'REVOKED')),
    version                   BIGINT NOT NULL DEFAULT 1,
    approver_principal_id     TEXT,
    approved_at               TIMESTAMPTZ,
    approver_auth_time        TIMESTAMPTZ,
    confirmed_at              TIMESTAMPTZ,
    confirmation_auth_time    TIMESTAMPTZ,
    confirmation_acr          TEXT,
    consumed_at               TIMESTAMPTZ,
    consumed_by_client        TEXT,
    ended_at                  TIMESTAMPTZ,
    end_reason                TEXT,
    created_at                TIMESTAMPTZ NOT NULL,
    CONSTRAINT action_approval_independent CHECK (approver_principal_id IS NULL
                                                  OR approver_principal_id <> initiator_principal_id),
    CONSTRAINT action_approval_deadline CHECK (deadline > created_at)
);
CREATE INDEX idx_action_approvals_initiator ON action_approvals (tenant_id, initiator_principal_id, status);
