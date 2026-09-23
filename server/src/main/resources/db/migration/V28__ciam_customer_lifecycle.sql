-- Canonical greenfield CIAM model: customer identities, one-time lifecycle
-- challenges, registered agent workloads, consented delegation grants, and
-- append-only lifecycle evidence.

CREATE TABLE customer_identities (
    id UUID PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES tenants(id),
    email VARCHAR(320) NOT NULL,
    display_name VARCHAR(200) NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    status VARCHAR(40) NOT NULL CHECK (status IN ('PENDING_VERIFICATION', 'ACTIVE', 'SUSPENDED', 'CLOSED')),
    email_verified_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    token_version BIGINT NOT NULL DEFAULT 1,
    revision BIGINT NOT NULL DEFAULT 0,
    CONSTRAINT uq_customer_identity_tenant_email UNIQUE (tenant_id, email),
    CONSTRAINT uq_customer_identity_tenant_id UNIQUE (tenant_id, id)
);

CREATE INDEX idx_customer_identity_tenant_status
    ON customer_identities (tenant_id, status);

CREATE TABLE customer_identity_challenges (
    id UUID PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    customer_id UUID NOT NULL,
    challenge_type VARCHAR(40) NOT NULL CHECK (challenge_type IN ('EMAIL_VERIFICATION', 'PASSWORD_RECOVERY')),
    token_hash VARCHAR(64) NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    used_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL,
    CONSTRAINT uq_customer_challenge_token_hash UNIQUE (token_hash),
    CONSTRAINT fk_customer_challenge_identity
        FOREIGN KEY (tenant_id, customer_id) REFERENCES customer_identities (tenant_id, id)
);

CREATE INDEX idx_customer_challenge_lookup
    ON customer_identity_challenges (tenant_id, challenge_type, token_hash);

CREATE TABLE agent_workload_identities (
    id UUID PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES tenants(id),
    workload_ref VARCHAR(255) NOT NULL,
    name VARCHAR(200) NOT NULL,
    oauth_client_id VARCHAR(255) NOT NULL,
    status VARCHAR(30) NOT NULL CHECK (status IN ('ACTIVE', 'REVOKED')),
    created_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ,
    revision BIGINT NOT NULL DEFAULT 0,
    CONSTRAINT uq_agent_workload_tenant_ref UNIQUE (tenant_id, workload_ref),
    CONSTRAINT uq_agent_workload_tenant_client UNIQUE (tenant_id, oauth_client_id),
    CONSTRAINT uq_agent_workload_tenant_id UNIQUE (tenant_id, id)
);

CREATE TABLE customer_delegation_grants (
    id UUID PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    customer_id UUID NOT NULL,
    agent_workload_id UUID NOT NULL,
    audience VARCHAR(255) NOT NULL,
    scopes JSONB NOT NULL,
    purpose VARCHAR(500) NOT NULL,
    status VARCHAR(30) NOT NULL CHECK (status IN ('ACTIVE', 'REVOKED', 'EXPIRED')),
    consent_recorded_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ,
    revocation_reason VARCHAR(500),
    created_at TIMESTAMPTZ NOT NULL,
    revision BIGINT NOT NULL DEFAULT 0,
    CONSTRAINT fk_delegation_grant_customer
        FOREIGN KEY (tenant_id, customer_id) REFERENCES customer_identities (tenant_id, id),
    CONSTRAINT fk_delegation_grant_workload
        FOREIGN KEY (tenant_id, agent_workload_id) REFERENCES agent_workload_identities (tenant_id, id),
    CONSTRAINT ck_delegation_expiry_after_consent CHECK (expires_at > consent_recorded_at)
);

CREATE INDEX idx_delegation_grant_customer_status
    ON customer_delegation_grants (tenant_id, customer_id, status);

CREATE TABLE ciam_lifecycle_events (
    id UUID PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    actor_id VARCHAR(255),
    event_type VARCHAR(80) NOT NULL,
    subject_type VARCHAR(80) NOT NULL,
    subject_id VARCHAR(255) NOT NULL,
    details JSONB NOT NULL DEFAULT '{}',
    correlation_id VARCHAR(255),
    occurred_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX idx_ciam_lifecycle_event_tenant_time
    ON ciam_lifecycle_events (tenant_id, occurred_at DESC);

CREATE OR REPLACE FUNCTION reject_ciam_lifecycle_event_mutation()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'CIAM lifecycle events are append-only';
END;
$$;

CREATE TRIGGER ciam_lifecycle_events_no_update
BEFORE UPDATE ON ciam_lifecycle_events
FOR EACH ROW EXECUTE FUNCTION reject_ciam_lifecycle_event_mutation();

CREATE TRIGGER ciam_lifecycle_events_no_delete
BEFORE DELETE ON ciam_lifecycle_events
FOR EACH ROW EXECUTE FUNCTION reject_ciam_lifecycle_event_mutation();
