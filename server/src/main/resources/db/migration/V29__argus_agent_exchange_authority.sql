-- Server-owned authority for explicit Argus Agent continuation and trusted
-- Gateway backend exchanges. Customer consent remains in the CIAM grant table.

CREATE TABLE trusted_exchange_brokers (
    id UUID PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES tenants(id),
    oauth_client_id VARCHAR(255) NOT NULL,
    gateway_audience VARCHAR(255) NOT NULL,
    allowed_scopes JSONB NOT NULL,
    status VARCHAR(30) NOT NULL CHECK (status IN ('ACTIVE', 'REVOKED')),
    created_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ,
    revision BIGINT NOT NULL DEFAULT 0,
    CONSTRAINT uq_exchange_broker_tenant_client UNIQUE (tenant_id, oauth_client_id),
    CONSTRAINT uq_exchange_broker_tenant_audience UNIQUE (tenant_id, gateway_audience)
);

CREATE TABLE agent_exchange_routes (
    id UUID PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    source_workload_id UUID NOT NULL,
    destination_type VARCHAR(30) NOT NULL CHECK (destination_type IN ('AGENT', 'RESOURCE', 'GATEWAY')),
    destination_workload_id UUID,
    audience VARCHAR(255) NOT NULL,
    allowed_scopes JSONB NOT NULL,
    purpose VARCHAR(500) NOT NULL,
    status VARCHAR(30) NOT NULL CHECK (status IN ('ACTIVE', 'REVOKED')),
    created_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ,
    revision BIGINT NOT NULL DEFAULT 0,
    CONSTRAINT fk_exchange_route_source
        FOREIGN KEY (tenant_id, source_workload_id) REFERENCES agent_workload_identities (tenant_id, id),
    CONSTRAINT fk_exchange_route_destination
        FOREIGN KEY (tenant_id, destination_workload_id) REFERENCES agent_workload_identities (tenant_id, id),
    CONSTRAINT ck_exchange_route_destination
        CHECK ((destination_type = 'AGENT' AND destination_workload_id IS NOT NULL)
            OR (destination_type IN ('RESOURCE', 'GATEWAY') AND destination_workload_id IS NULL)),
    CONSTRAINT ck_exchange_route_expiry CHECK (expires_at > created_at)
);

CREATE INDEX idx_exchange_route_source_target
    ON agent_exchange_routes (tenant_id, source_workload_id, audience, status);

CREATE UNIQUE INDEX uq_active_exchange_route
    ON agent_exchange_routes (tenant_id, source_workload_id, destination_type, audience)
    WHERE status = 'ACTIVE';
