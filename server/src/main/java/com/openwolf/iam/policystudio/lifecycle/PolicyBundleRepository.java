package com.openwolf.iam.policystudio.lifecycle;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

/**
 * The durable store of immutable policy-bundle records (Axiom Story C5). Append-only: a bundle is
 * written once at promotion and never mutated. The examiner resolves a decision's active policy version
 * to a record here; old versions remain available for the evidence-retention period even after a
 * rollback (rollback is a new promotion, not a delete).
 */
@Repository
public interface PolicyBundleRepository extends JpaRepository<PolicyBundleRecord, String> {

    List<PolicyBundleRecord> findByTenantIdOrderByCreatedAtDesc(String tenantId);
}
