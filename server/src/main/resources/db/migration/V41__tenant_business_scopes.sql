-- Tenant-scoped catalog of approved custom OAuth business-scope names (vocabulary only: a row grants no authority).
-- The deployment-configured list (iam.oauth2.approved-business-scopes) remains the baseline approved in every tenant.
CREATE TABLE tenant_business_scopes (
    id          UUID PRIMARY KEY,
    tenant_id   TEXT NOT NULL REFERENCES tenants(id),
    scope       VARCHAR(128) NOT NULL CHECK (scope ~ '^[a-z][a-z0-9-]*([.:][a-z][a-z0-9-]*)+$'),
    description VARCHAR(256),
    created_by  TEXT NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT tenant_business_scopes_unique UNIQUE (tenant_id, scope)
);
