-- Phase 3.2: structured, operator-registered purposes for customer consent. A purpose names exactly which scopes an
-- Agent workload may receive under it and the longest consent it may carry. Purpose-bound grants record the code and
-- who recorded the consent; grants created before this migration keep their free-text purpose and behave as before.
CREATE TABLE agent_workload_purposes (
    id                     UUID PRIMARY KEY,
    tenant_id              TEXT NOT NULL REFERENCES tenants(id),
    agent_workload_id      UUID NOT NULL REFERENCES agent_workload_identities(id),
    purpose_code           TEXT NOT NULL CHECK (purpose_code ~ '^[a-z][a-z0-9._-]{1,63}$'),
    description            TEXT NOT NULL,
    allowed_scopes         JSONB NOT NULL,
    max_validity_seconds   BIGINT NOT NULL CHECK (max_validity_seconds > 0 AND max_validity_seconds <= 7776000),
    status                 TEXT NOT NULL CHECK (status IN ('ACTIVE', 'RETIRED')),
    created_at             TIMESTAMPTZ NOT NULL,
    retired_at             TIMESTAMPTZ,
    revision               BIGINT NOT NULL DEFAULT 0,
    CONSTRAINT agent_workload_purpose_retired CHECK ((status = 'RETIRED') = (retired_at IS NOT NULL))
);
CREATE UNIQUE INDEX uq_agent_workload_purposes_code
    ON agent_workload_purposes (tenant_id, agent_workload_id, purpose_code);

ALTER TABLE customer_delegation_grants
    ADD COLUMN purpose_code TEXT,
    ADD COLUMN consent_source TEXT CHECK (consent_source IN ('CUSTOMER', 'ADMINISTRATOR'));
-- A purpose-bound grant is always recorded by the customer themself.
ALTER TABLE customer_delegation_grants ADD CONSTRAINT customer_delegation_purpose_consent
    CHECK (purpose_code IS NULL OR consent_source = 'CUSTOMER');
