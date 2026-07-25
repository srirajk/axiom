-- AXP-4: bounded inbound SCIM 2.0 provisioning authority.
CREATE TABLE scim_provisioning_sources (
    id UUID PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
    identity_source_id UUID REFERENCES identity_sources(id) ON DELETE RESTRICT,
    display_name TEXT NOT NULL,
    selector TEXT NOT NULL UNIQUE,
    secret_hash TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('ACTIVE', 'REVOKED')),
    revision BIGINT NOT NULL DEFAULT 1,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, display_name)
);

CREATE INDEX idx_scim_sources_tenant_status ON scim_provisioning_sources (tenant_id, status);

CREATE TABLE scim_resource_links (
    id UUID PRIMARY KEY,
    source_id UUID NOT NULL REFERENCES scim_provisioning_sources(id) ON DELETE RESTRICT,
    tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
    resource_type TEXT NOT NULL CHECK (resource_type IN ('User', 'Group')),
    external_id TEXT NOT NULL,
    resource_id TEXT NOT NULL,
    version BIGINT NOT NULL DEFAULT 1,
    managed_fields JSONB NOT NULL DEFAULT '[]',
    row_version BIGINT NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (source_id, resource_type, external_id),
    UNIQUE (source_id, resource_type, resource_id)
);

CREATE INDEX idx_scim_links_source_type ON scim_resource_links (source_id, resource_type);

ALTER TABLE principals ADD COLUMN scim_source_id UUID REFERENCES scim_provisioning_sources(id) ON DELETE RESTRICT;
ALTER TABLE principals ADD COLUMN scim_managed_fields JSONB NOT NULL DEFAULT '[]';
ALTER TABLE groups ADD COLUMN scim_source_id UUID REFERENCES scim_provisioning_sources(id) ON DELETE RESTRICT;
ALTER TABLE groups ADD COLUMN scim_managed_fields JSONB NOT NULL DEFAULT '[]';
