-- The protocol client id stays issuer-unique internally; one external CIMD URL may have independent application grants.
ALTER TABLE tenant_application_clients ADD COLUMN external_client_id TEXT;
CREATE UNIQUE INDEX uq_application_external_client ON tenant_application_clients (application_id, external_client_id)
    WHERE external_client_id IS NOT NULL AND status = 'ACTIVE';
CREATE INDEX idx_external_client ON tenant_application_clients (external_client_id) WHERE external_client_id IS NOT NULL;
ALTER TABLE oauth2_registered_client ALTER COLUMN client_settings TYPE TEXT;
ALTER TABLE oauth2_registered_client ALTER COLUMN redirect_uris TYPE TEXT;

-- Session inventory exposes the standards-defined URL rather than a synthetic storage id.
ALTER TABLE iam_sessions ALTER COLUMN client_id TYPE TEXT;
