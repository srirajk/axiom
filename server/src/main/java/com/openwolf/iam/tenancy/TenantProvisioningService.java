package com.openwolf.iam.tenancy;

import com.openwolf.iam.entity.Tenant;
import com.openwolf.iam.policystudio.lifecycle.PolicyBundleRepository;
import com.openwolf.iam.repository.TenantRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.Optional;

/**
 * Orchestrates atomic tenant provisioning / deprovisioning (Axiom Story B4 — the capstone).
 *
 * <p><b>Atomic visibility.</b> Creating a tenant stages three artifacts — a Cerbos deny-all policy
 * bootstrap ({@link PolicyBootstrapAdapter}), a Redis namespace ({@link TenantNamespaceAdapter}), and an audit partition
 * ({@link AuditPartitionAdapter}) — and only THEN flips the {@link ActiveTenantDirectory} with a
 * compare-and-set as the very LAST step. On an injected/crash failure the tenant is ABSENT from the
 * directory (so it resolves as unknown and every Axiom request under it fails closed at the authorization seam
 * with zero I/O — a half-provisioned tenant is fully unusable) AND the already-staged NON-AUDIT
 * artifacts are COMPENSATED (H6): the Redis namespace/index and staged policy bundle
 * are cleaned so a failed run leaves no orphaned artifact — not merely absence from the directory. The
 * AUDIT partition is append-only evidence and is never deleted. The persisted
 * {@link ProvisioningOperation} (keyed by idempotency key) records how far a run got; a retry with the
 * same key resumes and idempotently reconciles (content-addressed policy version + idempotent adapters
 * ⇒ one active tenant, no conflicting artifacts). The orchestration is deliberately a saga rather
 * than one long database transaction: the idempotency row is created and committed before external
 * staging, and each progress/failure ledger transition is committed independently. This prevents a
 * rollback-prone transaction from holding the idempotency-key row while a failure ledger waits on it.
 *
 * <p><b>Deprovision</b> reverses the order: remove the tenant from the directory FIRST (every Axiom
 * request then fails closed), wait for Axiom instances to acknowledge the new directory version, then clean
 * up the non-audit Redis artifact and retain the policy bundles for the evidence-retention
 * period. The audit partition is NEVER deleted — a deprovisioned tenant's evidence stays exportable.
 *
 * <p>This service owns activation/deactivation ordering only; the adapters own each artifact. It never
 * embeds domain knowledge — a tenant id is an opaque canonical string.
 */
@Service
public class TenantProvisioningService {

    private static final Logger log = LoggerFactory.getLogger(TenantProvisioningService.class);

    private final ProvisioningOperationRepository operations;
    private final ActiveTenantDirectory directory;
    private final PolicyBootstrapAdapter policyAdapter;
    private final TenantNamespaceAdapter namespaceAdapter;
    private final AuditPartitionAdapter auditAdapter;
    private final BootstrapPolicyPublisher policyPublisher;
    private final ProvisioningLedger ledger;
    private final PolicyBundleRepository policyBundles;
    private final TenantRepository tenants;

    @Autowired
    public TenantProvisioningService(ProvisioningOperationRepository operations,
                                     ActiveTenantDirectory directory,
                                     PolicyBootstrapAdapter policyAdapter,
                                     TenantNamespaceAdapter namespaceAdapter,
                                     AuditPartitionAdapter auditAdapter,
                                     BootstrapPolicyPublisher policyPublisher,
                                     ProvisioningLedger ledger,
                                     PolicyBundleRepository policyBundles,
                                     TenantRepository tenants) {
        this.operations = operations;
        this.directory = directory;
        this.policyAdapter = policyAdapter;
        this.namespaceAdapter = namespaceAdapter;
        this.auditAdapter = auditAdapter;
        this.policyPublisher = policyPublisher;
        this.ledger = ledger;
        this.policyBundles = policyBundles;
        this.tenants = tenants;
    }

    /** Direct adapter wiring used by provisioning tests that include the durable tenant catalogue. */
    public TenantProvisioningService(ProvisioningOperationRepository operations,
                                     ActiveTenantDirectory directory,
                                     PolicyBootstrapAdapter policyAdapter,
                                     TenantNamespaceAdapter namespaceAdapter,
                                     AuditPartitionAdapter auditAdapter,
                                     BootstrapPolicyPublisher policyPublisher,
                                     TenantRepository tenants) {
        this(operations, directory, policyAdapter, namespaceAdapter, auditAdapter, policyPublisher,
                new ProvisioningLedger(operations, directory, TenantLifecycleLockStore.noOp()), null, tenants);
    }

    /**
     * Provision (or reconcile a prior partial run of) a tenant. Idempotent on {@code idempotencyKey}:
     * a completed run returns the same active result; a failed/partial run resumes from the ledger.
     *
     * @throws ProvisioningException if a staging step fails — the tenant stays absent from the directory
     */
    public ProvisioningResult provision(ProvisioningRequest request, String idempotencyKey, String actor) {
        String key = requireKey(idempotencyKey);
        String tenantId = request.tenantId();

        ProvisioningLedger.ProvisioningLease run = ledger.startOrResumeProvision(key, request);
        ProvisioningOperation op = run.operation();
        TenantBootstrapBundle bundle = null;
        try {
            run.assertOwned();
            reconcileTenantCatalog(request);
            // Already fully provisioned — idempotent no-op (also self-heals the directory if needed).
            if (op.getStatus() == ProvisioningOperation.Status.ACTIVE && isRuntimeReconciled(op, tenantId)) {
                log.info("Provision '{}' (key {}) already ACTIVE — idempotent no-op", tenantId, key);
                return ProvisioningResult.of(op, directory.version());
            }

            // Track the staged policy bundle so a failure can COMPENSATE it (H6) — a failed run must leave
            // no orphaned staged artifact, not merely be absent from the directory.
            // ── Stage the three artifacts. Each adapter is idempotent, so a retry re-runs safely. ──

            // 1. Cerbos policy bootstrap — deny-all bundle, content-addressed, staged + probed.
            run.assertOwned();
            bundle = policyAdapter.stage(tenantId);
            run.assertOwned();
            policyAdapter.probe(bundle);
            op.setPolicyVersion(bundle.policyVersion());
            op.markStaged(ProvisioningOperation.Artifact.POLICY);
            ledger.saveProgress(op);

            // 2. Redis namespace + per-tenant index.
            run.assertOwned();
            namespaceAdapter.createNamespace(tenantId);
            run.assertOwned();
            op.markStaged(ProvisioningOperation.Artifact.REDIS);
            ledger.saveProgress(op);

            // 3. Audit partition (materialised by the genesis event).
            run.assertOwned();
            auditAdapter.recordProvisioned(tenantId, actor, op.getIdempotencyKey());
            run.assertOwned();
            op.markStaged(ProvisioningOperation.Artifact.AUDIT);
            ledger.saveProgress(op);

            // ── Verify all three before ANY visibility. A gap here keeps the tenant unusable. ──
            verifyAllStaged(op, tenantId);

            // ── Publish + serving-readiness probe + immutable C5 record BEFORE visibility. The exact
            // b_* id written into every policy is the pointer B4 activates and Studio later reviews.
            run.assertOwned();
            policyPublisher.publishAndPersist(bundle.policyBundle());
            run.assertOwned();

            // ── Activation compare-and-set — the LAST step. A retry after a post-CAS failure may find
            // the exact bootstrap already active; reconcile that state instead of stale-failing or
            // publishing a second identity. A different active id is a conflict and fails closed.
            String activeVersion = directory.find(tenantId).orElse(null);
            run.assertOwned();
            long directoryVersion = ledger.activate(op, tenantId, activeVersion, bundle.policyVersion());
            if (activeVersion != null) {
                log.info("Provision '{}' reconciled exact already-active bootstrap {} at directory v{}",
                        tenantId, activeVersion, directoryVersion);
            }
            log.info("Provisioned tenant '{}' — ACTIVE at directory v{} (policyVersion={})",
                    tenantId, directoryVersion, bundle.policyVersion());
            return ProvisioningResult.of(op, directoryVersion);

        } catch (RuntimeException e) {
            // COMPENSATE (H6): clean the already-staged NON-AUDIT artifacts so a failed run leaves no
            // orphaned Redis namespace/index or staged policy bundle — not merely absence from the
            // directory. Runs BEFORE the FAILED save so the durable ledger reflects the compensated state.
            // Never tear down Redis/policy artifacts underneath an active tenant. This matters
            // when a save/commit fails after the directory CAS: the transaction compensation may revert
            // the in-memory pointer later, but until then the tenant is live. Leaving idempotent artifacts
            // staged is safe and lets the retry reconcile; deleting active dependencies is not.
            boolean tenantVisible = directory.isActive(tenantId);
            boolean leaseOwned = ownsLease(run);
            if (!tenantVisible && leaseOwned) {
                compensateStaged(op, tenantId, bundle);
            } else {
                log.warn("Provision '{}' failed after activation; preserving staged/runtime dependencies "
                        + "while directory remains active or the lease is no longer owned for safe reconciliation",
                        tenantId);
            }

            // This service is a committed saga: repository.save() runs in its own transaction,
            // after the staged external work has been compensated and before the error escapes.
            if (leaseOwned) {
                ledger.markFailed(op, e);
            } else {
                log.error("Provision '{}' lost its lifecycle lease; refusing to overwrite a newer retry's ledger state",
                        tenantId);
            }
            // FAIL CLOSED: the tenant is NOT in the directory; a request under it resolves unknown at A2.
            log.warn("FAIL-CLOSED: provision of tenant '{}' failed after staging {} — staged artifacts {} "
                            + "and tenant directory active={} "
                            + "(retry key {} to reconcile): {}",
                    tenantId, op.stagedArtifacts(), tenantVisible ? "preserved" : "compensated",
                    tenantVisible, key, e.toString());
            throw (e instanceof ProvisioningException pe)
                    ? pe : new ProvisioningException("provisioning failed for tenant '" + tenantId + "'", e);
        } finally {
            ledger.release(run);
        }
    }

    /**
     * H6 compensation for a FAILED provision: clean up the NON-AUDIT artifacts already staged in this
     * run. Redis namespace/index and the staged policy bundle are debris from a never-activated run and
     * MUST NOT linger. The AUDIT partition is append-only
     * evidence (the genesis event) and is NEVER deleted — matching the deprovision contract. Each step
     * is best-effort and guarded so a cleanup failure never masks the original provisioning error.
     */
    private void compensateStaged(ProvisioningOperation op, String tenantId, TenantBootstrapBundle bundle) {
        if (op.isStaged(ProvisioningOperation.Artifact.REDIS)) {
            try {
                namespaceAdapter.removeNamespace(tenantId);
            } catch (RuntimeException ce) {
                log.warn("H6 compensation: failed to remove Redis namespace for '{}': {}", tenantId, ce.toString());
            }
        }
        if (bundle != null) {
            try {
                policyAdapter.discardStaged(bundle);
            } catch (RuntimeException ce) {
                log.warn("H6 compensation: failed to discard staged policy bundle {} for '{}': {}",
                        bundle.policyVersion(), tenantId, ce.toString());
            }
        }
    }

    /**
     * Deprovision a tenant: revoke visibility, retain audit. Idempotent on {@code idempotencyKey}.
     * Ordering (B4): directory deactivation is FIRST and waits for the directory-version acknowledgement
     * before deleting any non-audit artifact.
     */
    public void deprovision(String tenantId, String idempotencyKey, String actor) {
        String key = requireKey(idempotencyKey);
        ProvisioningLedger.ProvisioningLease run = ledger.startOrResumeDeprovision(key, tenantId);
        ProvisioningOperation op = run.operation();

        try {
            run.assertOwned();
            if (op.getStatus() == ProvisioningOperation.Status.DEACTIVATED) {
                log.info("Deprovision '{}' (key {}) already DEACTIVATED — idempotent no-op", tenantId, key);
                return;
            }
            // 1. FIRST: remove from the active directory. Every subsequent Axiom request fails closed.
            run.assertOwned();
            long revokedVersion = ledger.deactivate(tenantId);

            // 2. Wait for all Axiom instances to acknowledge the new directory version before touching artifacts.
            awaitDirectoryVersionAck(revokedVersion);

            // 3. Only now, clean up NON-AUDIT artifacts. Policy bundles are retained (evidence-retention).
            run.assertOwned();
            namespaceAdapter.removeNamespace(tenantId);

            // 4. The audit partition is NEVER deleted — record the deprovision as retained evidence.
            run.assertOwned();
            auditAdapter.recordDeprovisioned(tenantId, actor, op.getIdempotencyKey());
            run.assertOwned();

            ledger.markDeactivated(op);
            log.info("Deprovisioned tenant '{}' — directory revoked at v{}, non-audit artifacts cleaned, "
                    + "policy bundles + audit partition RETAINED", tenantId, revokedVersion);
        } catch (RuntimeException e) {
            // Persist the failed saga transition in its own repository transaction. There is no
            // suspended outer transaction holding this idempotency row, so replay cannot deadlock.
            if (ownsLease(run)) {
                ledger.markFailed(op, e);
            } else {
                log.error("Deprovision '{}' lost its lifecycle lease; refusing to overwrite a newer retry's ledger state",
                        tenantId);
            }
            throw e;
        } finally {
            ledger.release(run);
        }
    }

    public Optional<ProvisioningOperation> latestOperation(String tenantId) {
        return operations.findByTenantIdOrderByCreatedAtDesc(tenantId).stream().findFirst();
    }

    // ── internals ────────────────────────────────────────────────────────────────────────────

    private void verifyAllStaged(ProvisioningOperation op, String tenantId) {
        for (ProvisioningOperation.Artifact artifact : ProvisioningOperation.Artifact.values()) {
            if (!op.isStaged(artifact)) {
                throw new ProvisioningException("artifact " + artifact + " not staged for '" + tenantId + "'");
            }
        }
        if (!namespaceAdapter.namespaceExists(tenantId)) {
            throw new ProvisioningException("redis namespace missing for '" + tenantId + "'");
        }
        if (!auditAdapter.partitionExists(tenantId)) {
            throw new ProvisioningException("audit partition missing for '" + tenantId + "'");
        }
    }

    /**
     * The durable tenant catalogue is a prerequisite for tenant-owned product rows, but never a
     * serving-authority signal: only {@link ActiveTenantDirectory} determines whether requests run.
     * A retained row therefore remains valid after a failed or deprovisioned saga.
     */
    private void reconcileTenantCatalog(ProvisioningRequest request) {
        tenants.findById(request.tenantId()).ifPresentOrElse(existing -> {
            if (!existing.getName().equals(request.name()) || !existing.getSlug().equals(request.slug())) {
                throw new ProvisioningException("tenant '" + request.tenantId()
                        + "' is already catalogued with conflicting name or slug");
            }
        }, () -> {
            tenants.findBySlug(request.slug()).ifPresent(existing -> {
                throw new ProvisioningException("tenant slug '" + request.slug()
                        + "' is already catalogued for another tenant");
            });
            tenants.save(new Tenant(request.tenantId(), request.name(), request.slug(), "[]"));
        });
    }

    private boolean isRuntimeReconciled(ProvisioningOperation op, String tenantId) {
        if (!directory.isActive(tenantId) || !namespaceAdapter.namespaceExists(tenantId)
                || op.getPolicyVersion() == null) {
            return false;
        }
        return policyBundles == null || policyBundles.findById(op.getPolicyVersion()).isPresent();
    }

    /**
     * Single-instance: the directory swap is synchronous, so the new version is immediately
     * effective and the ack is a no-op. In a multi-instance deployment this blocks until every
     * Axiom replica reports it has installed a snapshot ≥ {@code version} (each replica polls the
     * directory out of band, A2). That fan-in is the deferred multi-instance seam.
     */
    protected void awaitDirectoryVersionAck(long version) {
        log.debug("Directory version v{} acked (single-instance; multi-instance fan-in is the seam)", version);
    }

    private static String requireKey(String idempotencyKey) {
        if (idempotencyKey == null || idempotencyKey.isBlank()) {
            throw new ProvisioningException("idempotency key is required");
        }
        return idempotencyKey.trim();
    }

    private static boolean ownsLease(ProvisioningLedger.ProvisioningLease run) {
        try {
            run.assertOwned();
            return true;
        } catch (ProvisioningException lost) {
            return false;
        }
    }

}
