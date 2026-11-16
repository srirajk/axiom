-- One server-owned CIMD client may be approved for several applications in its tenant.
-- Existing approvals remain valid; duplicate legacy rows may be consolidated by a reseed.
ALTER TABLE tenant_application_clients
    ADD COLUMN trusted_application_scopes jsonb NOT NULL DEFAULT '{}'::jsonb;
UPDATE tenant_application_clients
SET trusted_application_scopes = jsonb_build_object(application_id::text, allowed_scopes)
WHERE external_client_id IS NOT NULL;
