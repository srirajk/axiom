ALTER TABLE tenant_applications
    ADD COLUMN resource_uris jsonb NOT NULL DEFAULT '[]'::jsonb;

ALTER TABLE tenant_applications
    ADD CONSTRAINT tenant_applications_resource_uris_array
    CHECK (jsonb_typeof(resource_uris) = 'array');
