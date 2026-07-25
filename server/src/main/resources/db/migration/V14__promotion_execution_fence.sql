-- C5: durable execution fence spans the complete external promotion operation.
-- `lease_until` is diagnostic; the session advisory lock prevents live overlap and the durable row
-- prevents an uncertain/crashed owner from being silently replaced.
CREATE TABLE IF NOT EXISTS promotion_execution_locks (
    idempotency_key TEXT PRIMARY KEY,
    owner_key       TEXT NOT NULL,
    lease_until     TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_promotion_execution_lock_expiry
    ON promotion_execution_locks (lease_until);
