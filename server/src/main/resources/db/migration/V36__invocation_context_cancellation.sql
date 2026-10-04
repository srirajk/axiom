-- Phase 3.6: cancellation (a run/branch owner stopping work) is distinct from revocation (authority withdrawn).
-- Both end a context and its descendants for good; neither is ever reversed.
ALTER TABLE invocation_contexts ADD COLUMN cancelled_at TIMESTAMPTZ;
ALTER TABLE invocation_contexts DROP CONSTRAINT invocation_contexts_status_check;
ALTER TABLE invocation_contexts ADD CONSTRAINT invocation_contexts_status_check
    CHECK (status IN ('ACTIVE', 'REVOKED', 'CANCELLED'));
ALTER TABLE invocation_contexts ADD CONSTRAINT invocation_context_cancellation
    CHECK ((status = 'CANCELLED') = (cancelled_at IS NOT NULL));
