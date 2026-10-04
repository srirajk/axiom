-- Phase 2 repair: the destination audience is an immutable establishment fact. Resume and idempotent retry must match
-- it exactly, so it is stored with the context. Rows created before this migration have no recorded destination; they
-- can still be continued and revoked, but never resumed or retried (the comparison fails closed on NULL).
ALTER TABLE invocation_contexts ADD COLUMN destination_audience TEXT;
