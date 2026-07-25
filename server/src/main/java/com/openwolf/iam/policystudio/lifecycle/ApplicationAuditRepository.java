package com.openwolf.iam.policystudio.lifecycle;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.UUID;

/**
 * The durable application-audit index the examiner starts from (Axiom Story C5): resolve a recorded
 * decision by its {@code cerbosCallId}, or every decision in a request by {@code transactionId}.
 */
@Repository
public interface ApplicationAuditRepository extends JpaRepository<ApplicationAuditEntry, UUID> {

    List<ApplicationAuditEntry> findByCerbosCallId(String cerbosCallId);

    List<ApplicationAuditEntry> findByTransactionIdOrderByOccurredAt(String transactionId);
}
