package com.openwolf.iam.invocation;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

/**
 * Phase 2.3 authoritative invocation-context state. Every field except {@code status}, {@code version},
 * {@code revokedAt} and {@code revocationReason} is immutable after insert; status/version change only through
 * conditional {@code UPDATE}s in {@link InvocationContextRepository}, never through entity writes.
 */
@Entity
@Table(name = "invocation_contexts")
public class InvocationContext {
    public enum Status { ACTIVE, REVOKED, CANCELLED }

    @Id private UUID id;
    @Column(name = "tenant_id", nullable = false, updatable = false) private String tenantId;
    @Column(name = "parent_id", updatable = false) private UUID parentId;
    @Column(name = "root_id", nullable = false, updatable = false) private UUID rootId;
    @Column(nullable = false, updatable = false) private int depth;
    @Column(name = "security_scope", nullable = false, updatable = false) private String securityScope;
    @Column(name = "use_case_application_id", nullable = false, updatable = false) private UUID useCaseApplicationId;
    @Column(name = "entry_workload_id", nullable = false, updatable = false) private UUID entryWorkloadId;
    @Column(name = "originating_subject", nullable = false, updatable = false) private String originatingSubject;
    @Column(name = "identity_kind", nullable = false, updatable = false) private String identityKind;
    @Column(name = "root_session_id", updatable = false) private String rootSessionId;
    @Column(name = "broker_id", nullable = false, updatable = false) private UUID brokerId;
    @Column(name = "broker_client_id", nullable = false, updatable = false) private String brokerClientId;
    @Column(name = "gateway_route_id", nullable = false, updatable = false) private UUID gatewayRouteId;
    @Column(name = "destination_audience", updatable = false) private String destinationAudience;
    @JdbcTypeCode(SqlTypes.JSON)
    @Column(name = "authority_ceiling", nullable = false, updatable = false, columnDefinition = "jsonb")
    private List<String> authorityCeiling = new ArrayList<>();
    @Column(nullable = false, updatable = false) private Instant deadline;
    @Column(name = "max_depth", nullable = false, updatable = false) private int maxDepth;
    @Column(name = "run_ref", updatable = false) private String runRef;
    @Column(name = "branch_ref", updatable = false) private String branchRef;
    @Column(name = "authorization_reference", updatable = false) private String authorizationReference;
    @Column(name = "evidence_digest", updatable = false) private String evidenceDigest;
    @Column(name = "request_fingerprint", nullable = false, updatable = false) private String requestFingerprint;
    @Column(name = "idempotency_key", updatable = false) private String idempotencyKey;
    @Enumerated(EnumType.STRING) @Column(nullable = false, insertable = true, updatable = false) private Status status;
    @Column(nullable = false, updatable = false) private long version;
    @Column(name = "revoked_at", updatable = false) private Instant revokedAt;
    @Column(name = "revocation_reason", updatable = false) private String revocationReason;
    @Column(name = "created_at", nullable = false, updatable = false) private Instant createdAt;

    protected InvocationContext() {}

    /** Root context (one governed run). */
    static InvocationContext root(String tenantId, String securityScope, UUID useCaseApplicationId, UUID entryWorkloadId,
                                  String originatingSubject, String identityKind, String rootSessionId, UUID brokerId,
                                  String brokerClientId, UUID gatewayRouteId, String destinationAudience,
                                  List<String> ceiling, Instant deadline,
                                  int maxDepth, String runRef, String authorizationReference, String evidenceDigest,
                                  String requestFingerprint, String idempotencyKey, Instant now) {
        InvocationContext c = new InvocationContext();
        c.id = UUID.randomUUID();
        c.rootId = c.id;
        c.depth = 0;
        c.tenantId = tenantId; c.securityScope = securityScope; c.useCaseApplicationId = useCaseApplicationId;
        c.entryWorkloadId = entryWorkloadId; c.originatingSubject = originatingSubject; c.identityKind = identityKind;
        c.rootSessionId = rootSessionId; c.brokerId = brokerId; c.brokerClientId = brokerClientId;
        c.gatewayRouteId = gatewayRouteId; c.destinationAudience = destinationAudience;
        c.authorityCeiling = List.copyOf(ceiling); c.deadline = deadline;
        c.maxDepth = maxDepth; c.runRef = runRef; c.authorizationReference = authorizationReference;
        c.evidenceDigest = evidenceDigest; c.requestFingerprint = requestFingerprint; c.idempotencyKey = idempotencyKey;
        c.status = Status.ACTIVE; c.version = 1; c.createdAt = now;
        return c;
    }

    /** Branch: same immutable authority, attenuated ceiling, deadline no later than the parent's. */
    InvocationContext branch(String branchRef, List<String> ceiling, Instant now) {
        InvocationContext c = new InvocationContext();
        c.id = UUID.randomUUID();
        c.parentId = id; c.rootId = rootId; c.depth = depth + 1;
        c.tenantId = tenantId; c.securityScope = securityScope; c.useCaseApplicationId = useCaseApplicationId;
        c.entryWorkloadId = entryWorkloadId; c.originatingSubject = originatingSubject; c.identityKind = identityKind;
        c.rootSessionId = rootSessionId; c.brokerId = brokerId; c.brokerClientId = brokerClientId;
        c.gatewayRouteId = gatewayRouteId; c.destinationAudience = destinationAudience;
        c.authorityCeiling = List.copyOf(ceiling); c.deadline = deadline;
        c.maxDepth = maxDepth; c.runRef = runRef; c.branchRef = branchRef; c.authorizationReference = authorizationReference;
        c.requestFingerprint = requestFingerprint;
        c.status = Status.ACTIVE; c.version = 1; c.createdAt = now;
        return c;
    }

    public UUID getId() { return id; }
    public String getTenantId() { return tenantId; }
    public UUID getParentId() { return parentId; }
    public UUID getRootId() { return rootId; }
    public int getDepth() { return depth; }
    public String getSecurityScope() { return securityScope; }
    public UUID getUseCaseApplicationId() { return useCaseApplicationId; }
    public UUID getEntryWorkloadId() { return entryWorkloadId; }
    public String getOriginatingSubject() { return originatingSubject; }
    public String getIdentityKind() { return identityKind; }
    public String getRootSessionId() { return rootSessionId; }
    public UUID getBrokerId() { return brokerId; }
    public String getBrokerClientId() { return brokerClientId; }
    public UUID getGatewayRouteId() { return gatewayRouteId; }
    public String getDestinationAudience() { return destinationAudience; }
    public List<String> getAuthorityCeiling() { return List.copyOf(authorityCeiling); }
    public Instant getDeadline() { return deadline; }
    public int getMaxDepth() { return maxDepth; }
    public String getRunRef() { return runRef; }
    public String getBranchRef() { return branchRef; }
    public String getAuthorizationReference() { return authorizationReference; }
    public String getEvidenceDigest() { return evidenceDigest; }
    public String getRequestFingerprint() { return requestFingerprint; }
    public String getIdempotencyKey() { return idempotencyKey; }
    public Status getStatus() { return status; }
    public long getVersion() { return version; }
    public Instant getRevokedAt() { return revokedAt; }
    public String getRevocationReason() { return revocationReason; }
    public Instant getCreatedAt() { return createdAt; }
}
