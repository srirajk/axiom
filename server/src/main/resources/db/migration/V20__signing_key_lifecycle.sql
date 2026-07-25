-- AXP-5: deployment-scoped restart-safe RSA signing-key lifecycle.
CREATE TABLE signing_keys (
    id UUID PRIMARY KEY,
    deployment_id TEXT NOT NULL,
    kid TEXT NOT NULL,
    algorithm TEXT NOT NULL CHECK (algorithm = 'RS256'),
    state TEXT NOT NULL CHECK (state IN ('STAGED', 'ACTIVE', 'VERIFICATION_ONLY', 'RETIRED')),
    private_key_ciphertext TEXT,
    public_key_json JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    activated_at TIMESTAMPTZ,
    retired_at TIMESTAMPTZ,
    verification_expires_at TIMESTAMPTZ,
    revision BIGINT NOT NULL DEFAULT 1
);

CREATE UNIQUE INDEX uq_signing_keys_deployment_kid ON signing_keys (deployment_id, kid);
CREATE UNIQUE INDEX uq_signing_keys_one_active ON signing_keys (deployment_id) WHERE state = 'ACTIVE';
CREATE INDEX idx_signing_keys_verification_window ON signing_keys (deployment_id, state, verification_expires_at);
