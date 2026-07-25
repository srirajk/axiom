ALTER TABLE tenant_application_roles
    ADD COLUMN permission_effects JSONB NOT NULL DEFAULT '{}'::jsonb;

UPDATE tenant_application_roles
SET permission_effects = COALESCE((
    SELECT jsonb_object_agg(permission, 'allow')
    FROM jsonb_array_elements_text(permissions) AS permission
), '{}'::jsonb)
WHERE permission_effects = '{}'::jsonb;
