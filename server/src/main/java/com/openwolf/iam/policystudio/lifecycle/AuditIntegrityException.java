package com.openwolf.iam.policystudio.lifecycle;

/**
 * Thrown by the examiner chain when a recorded decision cannot be reconstructed end-to-end from the
 * immutable records (Axiom Story C5.1/C5.6). A missing call id, a mismatched active policy version, an
 * absent bundle/Git/approval/test record, or a broken join is an audit-integrity <b>FAILURE</b>, never a
 * warning — the chain either reconstructs completely from immutable records with no LLM, or it fails.
 */
public class AuditIntegrityException extends RuntimeException {
    public AuditIntegrityException(String message) {
        super(message);
    }
}
