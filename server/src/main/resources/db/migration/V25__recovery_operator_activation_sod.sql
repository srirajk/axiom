-- AXP-5 recovery SoD correction: prior V24 credentials were deliverable to an admin.
-- Invalidate them before the target-principal activation contract takes effect.
ALTER TABLE recovery_operators
    ALTER COLUMN credential_hash DROP NOT NULL;

ALTER TABLE recovery_operators
    ADD COLUMN initiator_principal_id TEXT,
    ADD COLUMN activation_actor_id TEXT,
    ADD COLUMN activation_at TIMESTAMPTZ;

ALTER TABLE recovery_operators
    DROP CONSTRAINT IF EXISTS recovery_operators_status_check,
    ADD CONSTRAINT ck_recovery_operators_status
        CHECK (status IN ('PENDING_ACTIVATION', 'ACTIVE', 'PENDING_ROTATION', 'DISABLED'));

UPDATE recovery_operators
   SET status = 'DISABLED', credential_hash = NULL, updated_at = now();

UPDATE iam_sessions
   SET status = 'REVOKED', revision = revision + 1
 WHERE recovery_marked = TRUE AND status = 'ACTIVE';
