-- Phase 1.2 credential boundary. Secret-bearing identity-control payloads used to be bound by a plain SHA-256 of the
-- canonical payload, stored and returned as payloadHash: anyone able to read it could test guesses of the secret
-- offline. New rows use a recovery-ID hash (supplied application-client rotations) or a keyed HMAC (identity-source
-- secrets). Legacy digests of secret-bearing payloads cannot be recomputed in SQL, so remove them and expire any
-- legacy request that could still be approved or applied; the operator re-proposes. APPLIED, REJECTED, CANCELLED
-- and EXPIRED history is kept; payload-free requests keep their constant SHA-256("{}") digest.
UPDATE identity_control_requests
   SET status = 'EXPIRED', revision = revision + 1
 WHERE payload_ciphertext IS NOT NULL
   AND status IN ('PENDING', 'APPROVED');

UPDATE identity_control_requests
   SET payload_hash = 'legacy-unkeyed-digest-removed'
 WHERE payload_ciphertext IS NOT NULL;
