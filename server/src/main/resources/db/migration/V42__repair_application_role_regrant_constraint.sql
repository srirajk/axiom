-- V17 created the active-only index but its DROP used an untruncated PostgreSQL
-- constraint name. Existing installations can retain the earlier full UNIQUE
-- constraint, which prevents a fresh grant after a role assignment is revoked.
DO $migration$
DECLARE
    obsolete_constraint text;
    obsolete_count integer;
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_index index_metadata
        JOIN pg_class index_relation ON index_relation.oid = index_metadata.indexrelid
        WHERE index_metadata.indrelid = 'tenant_application_role_assignments'::regclass
          AND index_relation.relname = 'uq_active_application_role_assignment'
          AND index_metadata.indisunique
          AND index_metadata.indpred IS NOT NULL
    ) THEN
        RAISE EXCEPTION 'active-only application role index is required before constraint repair';
    END IF;

    SELECT count(*), min(constraint_metadata.conname)
      INTO obsolete_count, obsolete_constraint
      FROM pg_constraint constraint_metadata
     WHERE constraint_metadata.conrelid = 'tenant_application_role_assignments'::regclass
       AND constraint_metadata.contype = 'u'
       AND pg_get_constraintdef(constraint_metadata.oid) =
           'UNIQUE (membership_id, application_role_id)';

    IF obsolete_count > 1 THEN
        RAISE EXCEPTION 'multiple obsolete application role constraints require review';
    END IF;
    IF obsolete_constraint IS NOT NULL THEN
        EXECUTE format('ALTER TABLE tenant_application_role_assignments DROP CONSTRAINT %I',
                       obsolete_constraint);
    END IF;
END
$migration$;
