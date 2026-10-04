-- IDP baseline: separate sign-in populations per interactive client, a confidential web (BFF) client type, and the
-- durable OAuth authorization-consent store that Spring Authorization Server expects (one row per client and
-- principal; the authorities column holds the granted scopes as SCOPE_* authorities).

ALTER TABLE tenant_application_clients DROP CONSTRAINT IF EXISTS tenant_application_clients_client_type_check;
ALTER TABLE tenant_application_clients ADD CONSTRAINT tenant_application_clients_client_type_check
    CHECK (client_type IN ('PUBLIC_BROWSER', 'CONFIDENTIAL_SERVICE', 'CONFIDENTIAL_WEB'));

-- Existing clients keep today's meaning: people of the workforce sign in through them.
ALTER TABLE tenant_application_clients
    ADD COLUMN population TEXT NOT NULL DEFAULT 'WORKFORCE' CHECK (population IN ('WORKFORCE', 'CUSTOMER'));

CREATE TABLE IF NOT EXISTS oauth2_authorization_consent (
    registered_client_id VARCHAR(100)  NOT NULL,
    principal_name       VARCHAR(200)  NOT NULL,
    authorities          VARCHAR(1000) NOT NULL,
    PRIMARY KEY (registered_client_id, principal_name)
);

-- private_key_jwt clients rotate by replacing their registered public keys, through the same two-person
-- identity-control flow as secret rotation.
ALTER TABLE identity_control_requests DROP CONSTRAINT IF EXISTS identity_control_requests_action_check;
ALTER TABLE identity_control_requests ADD CONSTRAINT identity_control_requests_action_check CHECK (action IN (
    'EMERGENCY_RETIRE_SIGNING_KEY', 'DISABLE_IDENTITY_SOURCE', 'ROTATE_IDENTITY_SOURCE_SECRET',
    'REVOKE_APPLICATION_CLIENT_SECRET', 'ROTATE_APPLICATION_CLIENT_SECRET',
    'REVOKE_SCIM_SOURCE', 'ROTATE_SCIM_SOURCE_CREDENTIAL', 'REPLACE_APPLICATION_CLIENT_KEYS'));
