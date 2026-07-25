package com.openwolf.iam.tenancy;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.openwolf.iam.entity.AuditLog;
import com.openwolf.iam.policystudio.lifecycle.PolicyBundleRecord;
import com.openwolf.iam.policystudio.lifecycle.PolicyBundleRepository;
import com.openwolf.iam.policystudio.lifecycle.PromotedBundleLoader;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * Governed, restart-safe recovery path for a crashed tenant lifecycle saga. The request carries only
 * the authenticated tenant context; all lock, directory, runtime, Redis and audit evidence is observed
 * server-side and persisted as immutable audit payload before a distinct authorized approver may clear it.
 */
@Service
public class LifecycleLockRecoveryService {

    static final String REQUESTED = "tenant.lifecycle_lock_recovery_requested";
    static final String APPROVED = "tenant.lifecycle_lock_recovery_approved";

    private final TenantLifecycleLockStore locks;
    private final ActiveTenantDirectory directory;
    private final TenantNamespaceAdapter namespaces;
    private final AuditPartitionAdapter audit;
    private final PolicyBundleRepository bundles;
    private final PromotedBundleLoader runtimeStore;
    private final ObjectMapper mapper;

    public LifecycleLockRecoveryService(TenantLifecycleLockStore locks,
                                        ActiveTenantDirectory directory,
                                        TenantNamespaceAdapter namespaces,
                                        AuditPartitionAdapter audit,
                                        PolicyBundleRepository bundles,
                                        PromotedBundleLoader runtimeStore,
                                        ObjectMapper mapper) {
        this.locks = locks;
        this.directory = directory;
        this.namespaces = namespaces;
        this.audit = audit;
        this.bundles = bundles;
        this.runtimeStore = runtimeStore;
        this.mapper = mapper;
    }

    public RecoveryResponse request(String tenantId, String operator) {
        Observation observation = observe(tenantId);
        if (!observation.lock().expired()) {
            throw new ProvisioningException("tenant lifecycle lock for '" + tenantId + "' has not expired");
        }
        if (!observation.safeToClear()) {
            throw new ProvisioningException("tenant '" + tenantId
                    + "' has contradictory or incomplete lifecycle state; recovery fails closed");
        }
        String correlationId = UUID.randomUUID().toString();
        String evidence = observation.payload(tenantId, mapper);
        String evidenceHash = sha256(evidence);
        String state = state(evidenceHash, evidence);
        audit.recordLifecycleLockRecoveryEvent(tenantId, operator, REQUESTED, correlationId, state);
        return new RecoveryResponse(correlationId, evidenceHash, observation.lock().ownerKey(),
                observation.lock().leaseUntil(), observation.namespacePresent(), observation.auditEventCount(),
                observation.bundleIds(), observation.runtime().backend(), observation.runtime().inventoryHash(),
                observation.auditInventoryHash());
    }

    public RecoveryResponse approve(String tenantId, String correlationId, String approver) {
        AuditLog request = audit.export(tenantId).stream()
                .filter(event -> REQUESTED.equals(event.getAction())
                        && correlationId.equals(event.getCorrelationId()))
                .findFirst()
                .orElseThrow(() -> new ProvisioningException("no lifecycle recovery request exists for correlation '"
                        + correlationId + "'"));
        if (approver.equals(request.getActorId())) {
            throw new ProvisioningException("separation of duties requires a distinct recovery approver");
        }
        JsonNode requested = parse(request.getAfterState());
        String expectedOwner = requested.path("evidence").path("owner_key").asText("");
        String requestedHash = requested.path("evidence_hash").asText("");
        String requestedEvidence = requested.path("evidence").toString();
        if (expectedOwner.isBlank() || requestedHash.isBlank() || requestedEvidence.isBlank()) {
            throw new ProvisioningException("lifecycle recovery request has incomplete immutable evidence");
        }

        Observation observation = observe(tenantId);
        if (!observation.lock().expired() || !observation.safeToClear()
                || !expectedOwner.equals(observation.lock().ownerKey())) {
            throw new ProvisioningException("lifecycle recovery evidence no longer matches current runtime state");
        }
        String currentEvidence = observation.payload(tenantId, mapper);
        if (!requestedHash.equals(sha256(currentEvidence)) || !requestedEvidence.equals(currentEvidence)) {
            throw new ProvisioningException("lifecycle recovery evidence changed; a fresh governed request is required");
        }

        String approvalPayload = state(requestedHash, currentEvidence, request.getActorId(), approver);
        TenantLifecycleLockStore.ReconciliationEvidence finalEvidence =
                new TenantLifecycleLockStore.ReconciliationEvidence(
                        request.getActorId(), approver, correlationId, requestedHash, approvalPayload,
                        observation.directoryVerified(), observation.runtimeVerified(),
                        observation.redisVerified(), observation.auditVerified());
        if (!locks.reconcileStale(tenantId, expectedOwner, finalEvidence)) {
            throw new ProvisioningException("lifecycle recovery did not clear the expected expired lock");
        }
        return new RecoveryResponse(correlationId, requestedHash, expectedOwner,
                observation.lock().leaseUntil(), observation.namespacePresent(), observation.auditEventCount(),
                observation.bundleIds(), observation.runtime().backend(), observation.runtime().inventoryHash(),
                observation.auditInventoryHash());
    }

    private Observation observe(String tenantId) {
        TenantLifecycleLockStore.LockObservation lock = locks.inspect(tenantId)
                .orElseThrow(() -> new ProvisioningException("no durable lifecycle lock exists for '" + tenantId + "'"));
        String activeVersion = directory.find(tenantId).orElse(null);
        boolean namespacePresent = namespaces.namespaceExists(tenantId);
        List<AuditLog> events = audit.export(tenantId);
        long domainAuditEvents = events.stream()
                .filter(event -> !event.getAction().startsWith("tenant.lifecycle_lock_recovery"))
                .count();
        String auditInventoryHash = auditInventoryHash(events);
        List<String> bundleIds = bundles.findByTenantIdOrderByCreatedAtDesc(tenantId).stream()
                .map(PolicyBundleRecord::getBundleId).sorted().toList();
        PromotedBundleLoader.RuntimeStoreSnapshot runtime = runtimeStore.snapshot();
        return new Observation(lock, activeVersion, runtime, namespacePresent, domainAuditEvents,
                auditInventoryHash, bundleIds, true, true, true, true);
    }

    private String state(String hash, String evidence) {
        return state(hash, evidence, null, null);
    }

    private String state(String hash, String evidence, String operator, String approver) {
        try {
            Map<String, Object> state = new LinkedHashMap<>();
            state.put("evidence_hash", hash);
            state.put("evidence", mapper.readTree(evidence));
            if (operator != null) state.put("operator_id", operator);
            if (approver != null) state.put("approver_id", approver);
            return mapper.writeValueAsString(state);
        } catch (Exception e) {
            throw new ProvisioningException("could not canonicalize lifecycle recovery evidence", e);
        }
    }

    private JsonNode parse(String json) {
        try {
            return mapper.readTree(json);
        } catch (Exception e) {
            throw new ProvisioningException("stored lifecycle recovery evidence is malformed", e);
        }
    }

    private static String sha256(String value) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256")
                    .digest(value.getBytes(StandardCharsets.UTF_8));
            StringBuilder out = new StringBuilder(digest.length * 2);
            for (byte b : digest) out.append(String.format("%02x", b));
            return out.toString();
        } catch (Exception e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }

    private String auditInventoryHash(List<AuditLog> events) {
        List<String> canonical = events.stream()
                .filter(event -> !event.getAction().startsWith("tenant.lifecycle_lock_recovery"))
                .sorted(java.util.Comparator.comparing(AuditLog::getOccurredAt)
                        .thenComparing(event -> String.valueOf(event.getId())))
                .map(event -> String.join("|", String.valueOf(event.getId()),
                        String.valueOf(event.getOccurredAt()), String.valueOf(event.getActorId()),
                        String.valueOf(event.getClientId()), String.valueOf(event.getAction()),
                        String.valueOf(event.getResourceType()), String.valueOf(event.getResourceId()),
                        String.valueOf(event.getBeforeState()), String.valueOf(event.getAfterState()),
                        String.valueOf(event.getCorrelationId())))
                .toList();
        return sha256(String.join("\n", canonical));
    }

    private record Observation(TenantLifecycleLockStore.LockObservation lock,
                               String activePolicyVersion,
                               PromotedBundleLoader.RuntimeStoreSnapshot runtime,
                               boolean namespacePresent,
                               long auditEventCount,
                               String auditInventoryHash,
                               List<String> bundleIds,
                               boolean directoryVerified,
                               boolean runtimeVerified,
                               boolean redisVerified,
                               boolean auditVerified) {
        boolean safeToClear() {
            return activePolicyVersion == null && !namespacePresent && runtime.objectCount() == 0
                    && directoryVerified && runtimeVerified && redisVerified && auditVerified;
        }

        String payload(String tenantId, ObjectMapper mapper) {
            Map<String, Object> state = new LinkedHashMap<>();
            state.put("tenant_id", tenantId);
            state.put("owner_key", lock.ownerKey());
            state.put("lease_until", lock.leaseUntil().toString());
            state.put("expired", lock.expired());
            state.put("directory_active", activePolicyVersion != null);
            state.put("active_policy_version", activePolicyVersion);
            state.put("directory_verified", directoryVerified);
            state.put("runtime_verified", runtimeVerified);
            state.put("runtime_backend", runtime.backend());
            state.put("runtime_object_count", runtime.objectCount());
            state.put("runtime_inventory_hash", runtime.inventoryHash());
            state.put("redis_namespace_present", namespacePresent);
            state.put("redis_verified", redisVerified);
            state.put("audit_event_count", auditEventCount);
            state.put("audit_inventory_hash", auditInventoryHash);
            state.put("audit_verified", auditVerified);
            state.put("policy_bundle_ids", bundleIds);
            try {
                return mapper.writeValueAsString(state);
            } catch (Exception e) {
                throw new ProvisioningException("could not canonicalize lifecycle observation", e);
            }
        }
    }

    public record RecoveryResponse(String correlationId, String evidenceHash, String ownerKey,
                                   Instant leaseUntil, boolean namespacePresent, long auditEventCount,
                                   List<String> policyBundleIds, String runtimeBackend,
                                   String runtimeInventoryHash, String auditInventoryHash) {}
}
