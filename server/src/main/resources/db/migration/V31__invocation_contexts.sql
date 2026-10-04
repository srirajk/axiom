-- Phase 2.3: minimal authoritative state for shared-Agent invocation contexts. Only security-relevant facts are stored:
-- immutable authority (tenant, security scope, Use Case, originating subject, root session, broker/route, ceiling,
-- deadline, depth bound) and the mutable status/version. Run IDs are caller-written labels; nothing records a
-- "current actor" (the actor lives in each token), so concurrent branches cannot overwrite one another.
CREATE TABLE invocation_contexts (
    id                       UUID PRIMARY KEY,
    tenant_id                TEXT NOT NULL REFERENCES tenants(id),
    parent_id                UUID REFERENCES invocation_contexts(id),
    root_id                  UUID NOT NULL,
    depth                    INT NOT NULL CHECK (depth >= 0),
    security_scope           TEXT NOT NULL,
    use_case_application_id  UUID NOT NULL,
    entry_workload_id        UUID NOT NULL,
    originating_subject      TEXT NOT NULL,
    identity_kind            TEXT NOT NULL,
    root_session_id          TEXT,
    broker_id                UUID NOT NULL,
    broker_client_id         TEXT NOT NULL,
    gateway_route_id         UUID NOT NULL,
    authority_ceiling        JSONB NOT NULL,
    deadline                 TIMESTAMPTZ NOT NULL,
    max_depth                INT NOT NULL CHECK (max_depth >= 0),
    run_ref                  TEXT,
    branch_ref               TEXT,
    authorization_reference  TEXT,
    evidence_digest          VARCHAR(64),
    request_fingerprint      VARCHAR(64) NOT NULL,
    idempotency_key          TEXT,
    status                   TEXT NOT NULL CHECK (status IN ('ACTIVE', 'REVOKED')),
    version                  BIGINT NOT NULL DEFAULT 1 CHECK (version >= 1),
    revoked_at               TIMESTAMPTZ,
    revocation_reason        TEXT,
    created_at               TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT invocation_context_root CHECK ((parent_id IS NULL) = (id = root_id)),
    CONSTRAINT invocation_context_revocation CHECK ((status = 'REVOKED') = (revoked_at IS NOT NULL))
);

-- Verified authorization evidence is single-purpose: one establishment per evidence value (keyed digest only).
CREATE UNIQUE INDEX uq_invocation_contexts_evidence
    ON invocation_contexts (tenant_id, evidence_digest) WHERE evidence_digest IS NOT NULL;
-- Issuance retries with the same idempotency key resolve to the same context.
CREATE UNIQUE INDEX uq_invocation_contexts_idempotency
    ON invocation_contexts (tenant_id, broker_client_id, idempotency_key) WHERE idempotency_key IS NOT NULL;
CREATE UNIQUE INDEX uq_invocation_contexts_branch
    ON invocation_contexts (parent_id, branch_ref) WHERE parent_id IS NOT NULL;
CREATE INDEX idx_invocation_contexts_session
    ON invocation_contexts (tenant_id, root_session_id, status);
CREATE INDEX idx_invocation_contexts_subject
    ON invocation_contexts (tenant_id, originating_subject, status);
CREATE INDEX idx_invocation_contexts_parent ON invocation_contexts (parent_id);
