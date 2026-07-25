package com.openwolf.iam.policystudio.lifecycle;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.UUID;

/**
 * The durable store of signed consequence approvals (Axiom Story C5) — the examiner's approvals/tests
 * hop. A promoted bundle is joined back to the approval that authorized it via the candidate bundle id.
 */
@Repository
public interface ApprovalRepository extends JpaRepository<ApprovalRecordEntity, UUID> {

    List<ApprovalRecordEntity> findByCandidateBundleId(String candidateBundleId);
}
