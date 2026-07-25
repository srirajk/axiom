-- AXP-3a: customer OIDC federation control-plane authority.
-- Secrets are encrypted references/material only; plaintext is never persisted.
CREATE TABLE identity_sources (
    id UUID PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
    display_name TEXT NOT NULL,
    issuer TEXT NOT NULL,
    discovery_uri TEXT NOT NULL,
    authorization_endpoint TEXT,
    token_endpoint TEXT,
    userinfo_endpoint TEXT,
    jwks_uri TEXT,
    client_id TEXT NOT NULL,
    client_secret_ciphertext TEXT NOT NULL,
    requested_scopes JSONB NOT NULL DEFAULT '["openid", "profile", "email"]',
    allowed_signing_algorithms JSONB NOT NULL DEFAULT '["RS256"]',
    required_claims JSONB NOT NULL DEFAULT '["sub", "iss", "aud", "exp", "iat", "nonce"]',
    required_acr_values JSONB NOT NULL DEFAULT '[]',
    status TEXT NOT NULL CHECK (status IN ('DRAFT', 'VALIDATED', 'ACTIVE', 'DISABLED')),
    revision BIGINT NOT NULL DEFAULT 1,
    last_validated_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, issuer),
    UNIQUE (tenant_id, display_name)
);

CREATE INDEX idx_identity_sources_tenant_status ON identity_sources (tenant_id, status);

CREATE TABLE external_identity_links (
    id UUID PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
    source_id UUID NOT NULL REFERENCES identity_sources(id) ON DELETE RESTRICT,
    issuer TEXT NOT NULL,
    subject TEXT NOT NULL,
    principal_id TEXT NOT NULL REFERENCES principals(id) ON DELETE RESTRICT,
    status TEXT NOT NULL CHECK (status IN ('ACTIVE', 'DISABLED')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (source_id, issuer, subject)
);

CREATE UNIQUE INDEX uq_external_identity_links_source_principal
    ON external_identity_links (source_id, principal_id);

CREATE INDEX idx_external_identity_links_tenant_principal
    ON external_identity_links (tenant_id, principal_id, status);
CREATE INDEX idx_external_identity_links_source_status
    ON external_identity_links (source_id, status);
