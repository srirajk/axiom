-- Align the durable payload hash column with IdentityControlRequest's VARCHAR(64) mapping.
-- PostgreSQL preserves the existing 64-character hash values, constraints, and indexes.
ALTER TABLE identity_control_requests
    ALTER COLUMN payload_hash TYPE VARCHAR(64);
