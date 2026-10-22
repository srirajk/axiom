-- Broker-owned audience allowlist. A revoked row remains as a migration fence:
-- legacy per-source routes must not revive a target that the broker administrator revoked.
CREATE UNIQUE INDEX uq_exchange_broker_tenant_id ON trusted_exchange_brokers (tenant_id, id);

CREATE TABLE trusted_exchange_broker_targets (
    id UUID PRIMARY KEY,
    broker_id UUID NOT NULL,
    tenant_id TEXT NOT NULL REFERENCES tenants(id),
    audience VARCHAR(255) NOT NULL,
    destination_type VARCHAR(30) NOT NULL CHECK (destination_type IN ('AGENT', 'RESOURCE')),
    destination_workload_id UUID,
    allowed_scopes JSONB NOT NULL,
    purpose VARCHAR(500) NOT NULL,
    status VARCHAR(30) NOT NULL CHECK (status IN ('ACTIVE', 'REVOKED')),
    created_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ,
    revision BIGINT NOT NULL DEFAULT 0,
    CONSTRAINT fk_broker_target_broker
        FOREIGN KEY (tenant_id, broker_id) REFERENCES trusted_exchange_brokers (tenant_id, id),
    CONSTRAINT fk_broker_target_destination
        FOREIGN KEY (tenant_id, destination_workload_id) REFERENCES agent_workload_identities (tenant_id, id),
    CONSTRAINT ck_broker_target_destination
        CHECK ((destination_type = 'AGENT' AND destination_workload_id IS NOT NULL)
            OR (destination_type = 'RESOURCE' AND destination_workload_id IS NULL))
);

CREATE INDEX idx_broker_target_lookup
    ON trusted_exchange_broker_targets (tenant_id, broker_id, audience, created_at DESC);

CREATE UNIQUE INDEX uq_active_broker_target
    ON trusted_exchange_broker_targets (broker_id, audience) WHERE status = 'ACTIVE';
