-- AXM-107: durable BUSY ownership across external provisioning/deprovisioning calls.
-- The lock is released on terminal completion. `lease_until` is diagnostic only: expiry never permits
-- automatic takeover because external systems do not accept a fencing token. A crashed process leaves
-- the tenant unavailable until an explicit two-person reconciliation records audit evidence and clears it.
CREATE TABLE IF NOT EXISTS tenant_lifecycle_locks (
    tenant_id   TEXT PRIMARY KEY,
    owner_key   TEXT NOT NULL,
    lease_until TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_tenant_lifecycle_lock_expiry
    ON tenant_lifecycle_locks (lease_until);

-- Provision/deprovision genesis evidence is immutable and idempotent on its saga correlation key.
CREATE UNIQUE INDEX IF NOT EXISTS uq_tenant_lifecycle_audit_event
    ON audit_log (tenant_id, action, resource_type, resource_id, correlation_id)
    WHERE action IN ('tenant.provisioned', 'tenant.deprovisioned',
                     'tenant.lifecycle_lock_recovery_requested',
                     'tenant.lifecycle_lock_recovery_approved',
                     'tenant.lifecycle_lock_reconciled')
      AND correlation_id IS NOT NULL;
