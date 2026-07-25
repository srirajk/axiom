package com.openwolf.iam.policystudio.lifecycle;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

/**
 * The durable Cerbos decision log (Axiom Story C5), keyed by {@code cerbosCallId} — the examiner's second
 * hop. A decision entry carries the {@code activePolicyVersion} the PDP evaluated under; the examiner
 * cross-checks it against the application audit's version.
 */
@Repository
public interface CerbosDecisionRepository extends JpaRepository<CerbosDecisionEntry, String> {
}
