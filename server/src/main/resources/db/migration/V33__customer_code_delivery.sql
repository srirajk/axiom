-- Phase 3.1: durable, protected delivery of customer verification/recovery codes through a provider adapter.
-- The code itself is stored only as AES-GCM ciphertext and only while a delivery is still PENDING; it is erased when
-- the delivery is sent or abandoned. The challenge row keeps its existing one-way hash for verification.
CREATE TABLE customer_code_deliveries (
    id                    UUID PRIMARY KEY,
    tenant_id             TEXT NOT NULL REFERENCES tenants(id),
    customer_id           UUID NOT NULL,
    challenge_id          UUID NOT NULL REFERENCES customer_identity_challenges(id),
    channel               TEXT NOT NULL CHECK (channel IN ('EMAIL')),
    purpose               TEXT NOT NULL CHECK (purpose IN ('EMAIL_VERIFICATION', 'PASSWORD_RECOVERY')),
    destination_digest    VARCHAR(64) NOT NULL,
    protected_code        TEXT,
    status                TEXT NOT NULL CHECK (status IN ('PENDING', 'SENT', 'ABANDONED')),
    attempts              INT NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    max_attempts          INT NOT NULL CHECK (max_attempts >= 1),
    next_attempt_at       TIMESTAMPTZ NOT NULL,
    lease_until           TIMESTAMPTZ,
    expires_at            TIMESTAMPTZ NOT NULL,
    provider              TEXT,
    provider_message_ref  TEXT,
    last_failure          TEXT,
    created_at            TIMESTAMPTZ NOT NULL,
    updated_at            TIMESTAMPTZ NOT NULL,
    sent_at               TIMESTAMPTZ,
    CONSTRAINT customer_code_delivery_payload CHECK ((status = 'PENDING') = (protected_code IS NOT NULL)),
    CONSTRAINT customer_code_delivery_sent CHECK ((status = 'SENT') = (sent_at IS NOT NULL))
);

CREATE UNIQUE INDEX uq_customer_code_deliveries_challenge ON customer_code_deliveries (challenge_id);
CREATE INDEX idx_customer_code_deliveries_due ON customer_code_deliveries (next_attempt_at) WHERE status = 'PENDING';
CREATE INDEX idx_customer_identity_challenges_issued
    ON customer_identity_challenges (tenant_id, customer_id, challenge_type, created_at);
