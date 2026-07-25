package com.openwolf.iam.tenancy;

import com.openwolf.iam.entity.AuditLog;

import java.util.List;

/**
 * The audit-partition artifact of tenant provisioning (Axiom B4, A6). Every tenant has a logical
 * audit partition — the {@code tenant_id}-scoped slice of {@code audit_log}. Provisioning records a
 * genesis event into it (which materialises the partition); deprovision NEVER deletes it — the
 * partition and its export outlive the tenant for the evidence-retention obligation.
 */
public interface AuditPartitionAdapter {

    /** Record the provisioning genesis event into the tenant's audit partition (idempotent-safe). */
    void recordProvisioned(String tenantId, String actor, String correlationId);

    /** Record the deprovisioning event — the partition is retained, so this APPENDS, never deletes. */
    void recordDeprovisioned(String tenantId, String actor, String correlationId);

    /** Record the two-person evidence-backed clearing of a crashed lifecycle BUSY row. */
    void recordLifecycleLockRecoveryEvent(String tenantId, String actor, String action,
                                           String correlationId, String payload);

    boolean partitionExists(String tenantId);

    /** Export the tenant's audit partition (A6) — usable AFTER deprovision; the records are retained. */
    List<AuditLog> export(String tenantId);
}
