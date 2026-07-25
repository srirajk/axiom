-- A revoked application-role assignment is historical evidence, not a permanent bar on a
-- subsequent reviewed grant. Only one active grant may exist for the exact membership/role pair.
ALTER TABLE tenant_application_role_assignments
    DROP CONSTRAINT IF EXISTS tenant_application_role_assignments_membership_id_application_role_id_key;

CREATE UNIQUE INDEX uq_active_application_role_assignment
    ON tenant_application_role_assignments (membership_id, application_role_id)
    WHERE revoked_at IS NULL;
