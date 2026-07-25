-- AXP-5: tenant-scoped, two-person identity-control request substrate.
CREATE TABLE identity_control_requests (
    id                         UUID PRIMARY KEY,
    tenant_id                  TEXT NOT NULL REFERENCES tenants(id),
    action                     TEXT NOT NULL CHECK (action IN (
        'EMERGENCY_RETIRE_SIGNING_KEY', 'DISABLE_IDENTITY_SOURCE', 'ROTATE_IDENTITY_SOURCE_SECRET',
        'REVOKE_APPLICATION_CLIENT_SECRET', 'ROTATE_APPLICATION_CLIENT_SECRET',
        'REVOKE_SCIM_SOURCE', 'ROTATE_SCIM_SOURCE_CREDENTIAL')),
    target_type                TEXT NOT NULL CHECK (target_type IN (
        'SIGNING_KEY', 'IDENTITY_SOURCE', 'APPLICATION_CLIENT', 'SCIM_SOURCE')),
    target_id                  UUID NOT NULL,
    payload_hash               CHAR(64) NOT NULL,
    payload_ciphertext         TEXT,
    initiator_principal_id     TEXT NOT NULL,
    created_at                 TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at                 TIMESTAMPTZ NOT NULL,
    expected_target_revision   BIGINT,
    status                     TEXT NOT NULL CHECK (status IN ('PENDING', 'APPROVED', 'APPLIED', 'REJECTED', 'EXPIRED', 'CANCELLED')),
    approver_principal_id      TEXT,
    approved_at                TIMESTAMPTZ,
    application_result_reference TEXT,
    revision                   BIGINT NOT NULL DEFAULT 1,
    CONSTRAINT identity_control_approval_pair CHECK ((approver_principal_id IS NULL) = (approved_at IS NULL))
);

CREATE INDEX idx_identity_control_requests_tenant_status
    ON identity_control_requests (tenant_id, status, created_at DESC);
CREATE INDEX idx_identity_control_requests_tenant_target
    ON identity_control_requests (tenant_id, target_type, target_id, status);
