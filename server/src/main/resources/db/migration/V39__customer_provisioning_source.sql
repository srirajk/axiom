-- How a customer identity came to exist. Self-registration and administrator provisioning are distinct facts;
-- neither implies a verified e-mail address (email_verified_at stays the only verification evidence).
ALTER TABLE customer_identities
    ADD COLUMN provisioning_source VARCHAR(20) NOT NULL DEFAULT 'SELF_REGISTRATION'
        CHECK (provisioning_source IN ('SELF_REGISTRATION', 'ADMINISTRATOR'));
