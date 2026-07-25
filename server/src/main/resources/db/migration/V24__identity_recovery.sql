-- AXP-5: tenant-scoped pre-enrolled identity recovery operators and session metadata.
CREATE TABLE recovery_operators (
    id             UUID PRIMARY KEY,
    tenant_id      TEXT NOT NULL REFERENCES tenants(id),
    principal_id   TEXT NOT NULL,
    credential_hash VARCHAR(255) NOT NULL,
    status         TEXT NOT NULL CHECK (status IN ('ACTIVE', 'DISABLED')),
    created_at     TIMESTAMPTZ NOT NULL,
    updated_at     TIMESTAMPTZ NOT NULL,
    revision       BIGINT NOT NULL DEFAULT 1,
    CONSTRAINT uq_recovery_operators_tenant_principal UNIQUE (tenant_id, principal_id),
    CONSTRAINT uq_recovery_operators_tenant_id UNIQUE (tenant_id, id),
    CONSTRAINT fk_recovery_operators_principal
        FOREIGN KEY (tenant_id, principal_id) REFERENCES principals (tenant_id, id)
);

CREATE INDEX idx_recovery_operators_tenant_status ON recovery_operators (tenant_id, status);

ALTER TABLE iam_sessions
    ADD COLUMN recovery_marked BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN recovery_scope VARCHAR(80),
    ADD COLUMN recovery_operator_a UUID,
    ADD COLUMN recovery_operator_b UUID;

ALTER TABLE iam_sessions
    ADD CONSTRAINT ck_iam_sessions_recovery_scope
    CHECK ((recovery_marked = FALSE AND recovery_scope IS NULL
            AND recovery_operator_a IS NULL AND recovery_operator_b IS NULL)
        OR (recovery_marked = TRUE AND recovery_scope = 'identity-admin'
            AND recovery_operator_a IS NOT NULL AND recovery_operator_b IS NOT NULL
            AND recovery_operator_a <> recovery_operator_b));

ALTER TABLE iam_sessions
    ADD CONSTRAINT fk_iam_sessions_recovery_operator_a
    FOREIGN KEY (tenant_id, recovery_operator_a)
    REFERENCES recovery_operators (tenant_id, id);

ALTER TABLE iam_sessions
    ADD CONSTRAINT fk_iam_sessions_recovery_operator_b
    FOREIGN KEY (tenant_id, recovery_operator_b)
    REFERENCES recovery_operators (tenant_id, id);
