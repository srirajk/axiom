package com.openwolf.iam.invocation;

import com.openwolf.iam.security.SecretProtector;
import com.openwolf.iam.service.AuditService;
import com.openwolf.iam.service.TenantApplicationService;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.dao.DataAccessException;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.TreeSet;
import java.util.UUID;

/**
 * Phase 2.2-2.11 Axiom-side invocation-context authority. Every decision reads current PostgreSQL state; there is no
 * cache, so there is no allow-on-miss path and no staleness window inside Axiom (Phase 0.5). Any missing, unreadable,
 * mismatched, stale, revoked or expired state fails closed with {@code invalid_grant}.
 */
@Service
public class InvocationContextService {
    public static final String CLAIM_CONTEXT = "ctx";
    public static final String CLAIM_VERSION = "ctx_ver";
    public static final String CLAIM_DEPTH = "ctx_depth";
    public static final String LIMIT_EXCEEDED = "invocation_limit_exceeded";
    private static final int MAX_LABEL = 128;

    private final InvocationContextRepository contexts;
    private final InvocationAuthorizationVerifier verifier;
    private final TenantApplicationService applications;
    private final SecretProtector secrets;
    private final AuditService audit;
    private final Clock clock;
    private final Duration maxLifetime;
    private final int maxDepth;
    private final int maxBranches;
    private final int maxActivePerSession;

    @org.springframework.beans.factory.annotation.Autowired
    public InvocationContextService(InvocationContextRepository contexts, InvocationAuthorizationVerifier verifier,
                                    TenantApplicationService applications, SecretProtector secrets, AuditService audit,
                                    @Value("${iam.invocation-context.max-lifetime:PT1H}") Duration maxLifetime,
                                    @Value("${iam.invocation-context.max-depth:4}") int maxDepth,
                                    @Value("${iam.invocation-context.max-branches:8}") int maxBranches,
                                    @Value("${iam.invocation-context.max-active-per-session:32}") int maxActivePerSession) {
        this(contexts, verifier, applications, secrets, audit, Clock.systemUTC(), maxLifetime, maxDepth, maxBranches,
                maxActivePerSession);
    }

    InvocationContextService(InvocationContextRepository contexts, InvocationAuthorizationVerifier verifier,
                             TenantApplicationService applications, SecretProtector secrets, AuditService audit,
                             Clock clock, Duration maxLifetime, int maxDepth, int maxBranches, int maxActivePerSession) {
        if (maxLifetime.isNegative() || maxLifetime.isZero() || maxDepth < 0 || maxBranches < 0 || maxActivePerSession < 1) {
            throw new IllegalArgumentException("invocation-context limits must be positive");
        }
        this.contexts = contexts; this.verifier = verifier; this.applications = applications; this.secrets = secrets;
        this.audit = audit; this.clock = clock; this.maxLifetime = maxLifetime; this.maxDepth = maxDepth;
        this.maxBranches = maxBranches; this.maxActivePerSession = maxActivePerSession;
    }

    /** Context binding of one issued token. */
    public record Binding(UUID contextId, long version, int tokenDepth, Instant deadline, Set<String> ceiling,
                          boolean created) {}

    /** Optional, strictly parsed token-request parameters. Labels are non-authoritative. */
    public record Request(String evidence, String runRef, Long ttlSeconds, String idempotencyKey, String branchRef,
                          String resumeContextId) {
        public static final Request NONE = new Request(null, null, null, null, null, null);
        public boolean establishes() { return evidence != null || resumeContextId != null; }
        public boolean any() { return establishes() || runRef != null || ttlSeconds != null || idempotencyKey != null
                || branchRef != null; }
    }

    /** Facts Axiom has already verified for a broker establishing or resuming a context from a Gateway token. */
    public record Establishment(String tenantId, String brokerClientId, UUID brokerId, String securityScope,
                                UUID gatewayRouteId, Jwt subject, String entryClientId, UUID entryWorkloadId,
                                String destinationAudience, Set<String> requestedScopes) {}

    /** Denial that carries an internal reason for audit; the caller sees only the OAuth error code. */
    public static final class Denied extends OAuth2AuthenticationException {
        private final String reason;

        Denied(String errorCode, String reason) {
            super(new OAuth2Error(errorCode));
            this.reason = reason;
        }

        public String reason() { return reason; }
    }

    // =================================================================================================================
    // Establishment (2.2) and resume
    // =================================================================================================================

    @Transactional
    public Binding establish(Establishment in, Request request) {
        Jwt subject = in.subject();
        if (subject.getClaims().containsKey(CLAIM_CONTEXT)) throw deny("subject token is already context-bound");
        if (!"gateway_authorization".equals(subject.getClaimAsString("token_use"))) throw deny("establishment needs a Gateway authorization");
        String rootSession = subject.getClaimAsString("subject_sid");
        String identityKind = subject.getClaimAsString("identity_kind");
        if ("workforce".equals(identityKind) && (rootSession == null || rootSession.isBlank())) throw deny("missing root session");
        UUID useCase = applications.activeAuthority(in.entryClientId())
                .filter(a -> a.tenantId().equals(in.tenantId())).map(TenantApplicationService.ClientAuthority::applicationId)
                .orElseThrow(() -> deny("entry caller is not an active application client"));
        Instant now = clock.instant();
        if (request.resumeContextId() != null) return resume(in, request, useCase, rootSession, now);

        String fingerprint = fingerprint(in, useCase, rootSession);
        if (request.idempotencyKey() != null) {
            contexts.lock("invocation-idem|" + in.tenantId() + "|" + in.brokerClientId() + "|" + request.idempotencyKey());
            var existing = contexts.findByTenantIdAndBrokerClientIdAndIdempotencyKey(in.tenantId(), in.brokerClientId(),
                    request.idempotencyKey());
            if (existing.isPresent()) {
                InvocationContext c = existing.get();
                if (!c.getRequestFingerprint().equals(fingerprint) || !sameEstablishment(c, in, useCase, rootSession)) {
                    throw deny("idempotency key reused for a different request");
                }
                requireUsable(chainOf(c), now);
                return new Binding(c.getId(), c.getVersion(), 0, c.getDeadline(), Set.copyOf(c.getAuthorityCeiling()), false);
            }
        }
        if (request.evidence() == null) throw deny("verified authorization is required to establish a context");
        String evidenceDigest = secrets.keyedDigest("invocation-evidence", request.evidence());
        contexts.lock("invocation-evidence|" + in.tenantId() + "|" + evidenceDigest);
        if (contexts.findByTenantIdAndEvidenceDigest(in.tenantId(), evidenceDigest).isPresent()) {
            throw deny("authorization evidence was already used");
        }
        Instant requestedDeadline = now.plus(request.ttlSeconds() == null ? maxLifetime
                : minimum(Duration.ofSeconds(request.ttlSeconds()), maxLifetime));
        InvocationAuthorizationVerifier.Verified verified;
        try {
            verified = verifier.verify(new InvocationAuthorizationVerifier.EstablishmentClaim(in.tenantId(),
                    in.brokerClientId(), in.securityScope(), subject.getSubject(), rootSession, useCase, in.entryWorkloadId(),
                    in.destinationAudience(), Set.copyOf(in.requestedScopes()), requestedDeadline), request.evidence());
        } catch (InvocationAuthorizationVerifier.Rejected rejected) {
            throw deny("authorization not verified: " + rejected.getMessage());
        } catch (RuntimeException unavailable) {
            throw deny("authorization verifier unavailable");
        }
        if (verified == null || verified.notAfter() == null || verified.approvedScopes() == null) throw deny("incomplete verification");
        Set<String> ceiling = new TreeSet<>(verified.approvedScopes());
        ceiling.retainAll(scopes(subject));
        if (!ceiling.containsAll(in.requestedScopes())) throw deny("requested scope exceeds the verified authority");
        Instant deadline = earliest(requestedDeadline, verified.notAfter());
        if (!deadline.isAfter(now)) throw deny("verified authorization has expired");

        contexts.lock("invocation-session|" + in.tenantId() + "|" + subject.getSubject() + "|" + rootSession);
        if (contexts.countActiveRoots(in.tenantId(), subject.getSubject(), rootSession, now) >= maxActivePerSession) {
            throw new Denied(LIMIT_EXCEEDED, "active contexts per session exhausted");
        }
        InvocationContext created = contexts.saveAndFlush(InvocationContext.root(in.tenantId(), in.securityScope(), useCase,
                in.entryWorkloadId(), subject.getSubject(), identityKind, rootSession, in.brokerId(), in.brokerClientId(),
                in.gatewayRouteId(), in.destinationAudience(), List.copyOf(ceiling), deadline, maxDepth, label(request.runRef()),
                label(verified.reference()), evidenceDigest, fingerprint, request.idempotencyKey(), now));
        audit.logRequired(in.tenantId(), in.brokerClientId(), "INVOCATION_CONTEXT_ESTABLISHED", "invocation_context",
                created.getId().toString(), null, snapshot(created), created.getId().toString());
        return new Binding(created.getId(), created.getVersion(), 0, deadline, Set.copyOf(ceiling), true);
    }

    private Binding resume(Establishment in, Request request, UUID useCase, String rootSession, Instant now) {
        UUID id = uuid(request.resumeContextId());
        InvocationContext c = contexts.findByIdAndTenantId(id, in.tenantId()).orElseThrow(() -> deny("unknown context"));
        requireUsable(chainOf(c), now);
        // Context ID possession grants nothing: a fresh Gateway authorization must match every immutable fact.
        if (c.getParentId() != null || !sameEstablishment(c, in, useCase, rootSession)) {
            throw deny("resume does not match the context");
        }
        if (!Set.copyOf(c.getAuthorityCeiling()).containsAll(in.requestedScopes())) throw deny("resume widens the ceiling");
        return new Binding(c.getId(), c.getVersion(), 0, c.getDeadline(), Set.copyOf(c.getAuthorityCeiling()), false);
    }

    // =================================================================================================================
    // Continuation (2.5/2.6) and branches (2.11)
    // =================================================================================================================

    /**
     * A continuation from a context-bound subject token. The edge itself (workload, recipient, route, broker) has
     * already been verified by the exchange authority; this adds context ownership, version, status, deadline,
     * attenuation and depth.
     */
    @Transactional
    public Binding continueFrom(Jwt subject, Set<String> requestedScopes, String branchRef) {
        Instant now = clock.instant();
        List<InvocationContext> chain = boundChain(subject, now);
        InvocationContext c = chain.getFirst();
        int depth = depthOf(subject) + 1;
        if (depth > c.getMaxDepth()) throw deny("delegation depth exceeded");
        if (!Set.copyOf(c.getAuthorityCeiling()).containsAll(requestedScopes)) throw deny("scope widens the context ceiling");
        if (branchRef == null) {
            return new Binding(c.getId(), c.getVersion(), depth, c.getDeadline(), Set.copyOf(c.getAuthorityCeiling()), false);
        }
        String ref = label(branchRef);
        // Serialize with every revocation path of this tree; then re-read the chain under the lock.
        contexts.lockRoot(c.getRootId(), c.getTenantId()).orElseThrow(() -> deny("unknown context"));
        var existing = contexts.findByParentIdAndBranchRef(c.getId(), ref);
        if (existing.isPresent()) {
            InvocationContext b = existing.get();
            if (!Set.copyOf(b.getAuthorityCeiling()).containsAll(requestedScopes)) throw deny("scope widens the branch ceiling");
            if (contexts.inactiveInChain(b.getId(), b.getTenantId()) > 0) throw deny("context revoked");
            return new Binding(b.getId(), b.getVersion(), depth, b.getDeadline(), Set.copyOf(b.getAuthorityCeiling()), false);
        }
        if (c.getDepth() + 1 > c.getMaxDepth()) throw deny("branch nesting exceeded");
        if (contexts.countByParentId(c.getId()) >= maxBranches) throw new Denied(LIMIT_EXCEEDED, "fan-out exhausted");
        // Re-check under the root lock with a scalar read (not cached entities): a revoke that committed while this
        // transaction waited for the lock is observed here, before any child is created.
        if (contexts.inactiveInChain(c.getId(), c.getTenantId()) > 0) throw deny("context revoked");
        InvocationContext child = contexts.saveAndFlush(c.branch(ref, List.copyOf(new TreeSet<>(requestedScopes)), now));
        probe(InvocationContextRaceProbe.BRANCH_INSERTED, child.getId());
        audit.logRequired(c.getTenantId(), subject.getClaimAsString("client_id"), "INVOCATION_CONTEXT_BRANCHED",
                "invocation_context", child.getId().toString(), null, snapshot(child), child.getRootId().toString());
        return new Binding(child.getId(), child.getVersion(), depth, child.getDeadline(),
                Set.copyOf(child.getAuthorityCeiling()), true);
    }

    /** Decode/introspection-time check for any context-bound token: current, owned, unexpired, not revoked. */
    @Transactional(readOnly = true)
    public void requireCurrent(Jwt token) {
        boundChain(token, clock.instant());
    }

    /**
     * Context facts for the token's intended recipient only (recipient = the client whose application audience is the
     * token's single audience). Anyone else learns nothing, even with a valid token.
     */
    @Transactional(readOnly = true)
    public Map<String, Object> project(Jwt token, String callerClientId) {
        InvocationContext c = boundChain(token, clock.instant()).getFirst();
        String audience = token.getAudience() == null || token.getAudience().size() != 1 ? null : token.getAudience().getFirst();
        boolean recipient = audience != null && applications.activeAuthority(callerClientId)
                .filter(a -> a.tenantId().equals(c.getTenantId())).filter(a -> audience.equals(a.audience())).isPresent();
        if (!recipient) throw deny("caller is not the token's recipient");
        Map<String, Object> facts = new LinkedHashMap<>();
        facts.put("id", c.getId().toString());
        facts.put("version", c.getVersion());
        facts.put("status", c.getStatus().name());
        facts.put("root_id", c.getRootId().toString());
        facts.put("security_scope", c.getSecurityScope());
        facts.put("use_case_application_id", c.getUseCaseApplicationId().toString());
        facts.put("originating_subject", c.getOriginatingSubject());
        facts.put("authority_ceiling", c.getAuthorityCeiling());
        facts.put("deadline", c.getDeadline().getEpochSecond());
        facts.put("token_depth", depthOf(token));
        return facts;
    }

    // =================================================================================================================
    // Revocation (2.9)
    // =================================================================================================================

    @Transactional
    public int revoke(String tenantId, UUID contextId, String reason, String actor) {
        InvocationContext c = contexts.findByIdAndTenantId(contextId, tenantId).orElse(null);
        if (c == null) return 0;
        // Waits for any in-flight branch creation in this tree to commit, so the cascade below sees its row.
        contexts.lockRoot(c.getRootId(), tenantId);
        probe(InvocationContextRaceProbe.REVOKE_LOCKED, contextId);
        int revoked = contexts.revokeTree(contextId, tenantId, label(reason), clock.instant());
        audit.logRequired(tenantId, actor, "INVOCATION_CONTEXT_REVOKED", "invocation_context", contextId.toString(),
                null, Map.of("reason", label(reason), "revoked_contexts", revoked, "root_id", c.getRootId().toString()),
                c.getRootId().toString());
        return revoked;
    }

    /**
     * Phase 3.6 cancellation by the broker that established the run: the context and its descendants stop; its parent,
     * siblings, other runs and the human session are untouched. Cancellation is distinct from revocation (status
     * CANCELLED, its own audit event) and, like revocation, permanent and idempotent.
     */
    @Transactional
    public int cancelByBroker(String tenantId, UUID contextId, String brokerClientId, String reason) {
        InvocationContext c = contexts.findByIdAndTenantId(contextId, tenantId)
                .filter(value -> value.getBrokerClientId().equals(brokerClientId))
                .orElseThrow(() -> new org.springframework.security.access.AccessDeniedException(
                        "context was not established by this broker"));
        contexts.lockRoot(c.getRootId(), tenantId);
        probe(InvocationContextRaceProbe.REVOKE_LOCKED, contextId);
        String why = label(reason == null || reason.isBlank() ? "cancelled by broker" : reason);
        int cancelled = contexts.cancelTree(contextId, tenantId, why, clock.instant());
        if (cancelled > 0) {
            audit.logRequired(tenantId, brokerClientId, "INVOCATION_CONTEXT_CANCELLED", "invocation_context",
                    contextId.toString(), null, Map.of("reason", why, "cancelled_contexts", cancelled,
                            "root_id", c.getRootId().toString(), "branch", c.getParentId() != null),
                    c.getRootId().toString());
        }
        return cancelled;
    }

    /**
     * Phase 3.4: authority a durable task may bind to — a current context whose run was established for the calling
     * Agent (its audience is the run's destination). Returns the context version and originating subject.
     */
    @Transactional(readOnly = true)
    public TaskAuthority taskAuthority(String tenantId, UUID contextId, String recipientAudience) {
        InvocationContext c = contexts.findByIdAndTenantId(contextId, tenantId)
                .orElseThrow(() -> new org.springframework.security.access.AccessDeniedException("context is not current"));
        List<InvocationContext> chain = chainOf(c);
        try {
            requireUsable(chain, clock.instant());
        } catch (Denied denied) {
            throw new org.springframework.security.access.AccessDeniedException("context is not current");
        }
        InvocationContext root = chain.getLast();
        if (recipientAudience == null || !recipientAudience.equals(root.getDestinationAudience())) {
            throw new org.springframework.security.access.AccessDeniedException("context is not current");
        }
        return new TaskAuthority(c.getVersion(), c.getOriginatingSubject());
    }

    public record TaskAuthority(long version, String originatingSubject) {}

    /** Logout or administrative revocation of the root session ends every run it started. */
    @Transactional
    public int revokeForRootSession(String tenantId, UUID sessionId, String reason) {
        contexts.lockRootsForSession(tenantId, sessionId.toString());
        probe(InvocationContextRaceProbe.REVOKE_LOCKED, sessionId);
        int revoked = contexts.revokeForRootSession(tenantId, sessionId.toString(), label(reason), clock.instant());
        if (revoked > 0) {
            audit.logRequired(tenantId, "system", "INVOCATION_CONTEXT_REVOKED", "iam_session", sessionId.toString(),
                    null, Map.of("reason", label(reason), "revoked_contexts", revoked), sessionId.toString());
        }
        return revoked;
    }

    /** Identity disable ends every run the subject started. (Assignment removal does not: see the 2.1 contract.) */
    @Transactional
    public int revokeForSubject(String tenantId, String subject, String reason) {
        contexts.lockRootsForSubject(tenantId, subject);
        probe(InvocationContextRaceProbe.REVOKE_LOCKED, null);
        int revoked = contexts.revokeForSubject(tenantId, subject, label(reason), clock.instant());
        if (revoked > 0) {
            audit.logRequired(tenantId, "system", "INVOCATION_CONTEXT_REVOKED", "principal", subject,
                    null, Map.of("reason", label(reason), "revoked_contexts", revoked), subject);
        }
        return revoked;
    }

    @Transactional(readOnly = true)
    public Map<String, Object> describe(String tenantId, UUID contextId) {
        return contexts.findByIdAndTenantId(contextId, tenantId).map(InvocationContextService::snapshot)
                .orElseThrow(() -> new com.openwolf.iam.exception.EntityNotFoundException("Invocation context not found"));
    }

    // =================================================================================================================
    // Helpers
    // =================================================================================================================

    private List<InvocationContext> boundChain(Jwt token, Instant now) {
        UUID id = uuid(token.getClaimAsString(CLAIM_CONTEXT));
        String tenantId = token.getClaimAsString("tenant_id");
        Object rawVersion = token.getClaims().get(CLAIM_VERSION);
        if (tenantId == null || !(rawVersion instanceof Number version)) throw deny("malformed context claims");
        List<InvocationContext> chain;
        try {
            chain = contexts.chain(id, tenantId);
        } catch (DataAccessException unavailable) {
            throw deny("context state unavailable");
        }
        if (chain.isEmpty()) throw deny("unknown context");
        requireChainShape(chain, id);
        InvocationContext c = chain.getFirst();
        if (c.getVersion() != version.longValue()) throw deny("stale context version");
        requireUsable(chain, now);
        if (!c.getOriginatingSubject().equals(token.getSubject())
                || !Objects.equals(c.getRootSessionId(), rootSessionOf(token))) throw deny("context owner mismatch");
        if (token.getExpiresAt() != null && token.getExpiresAt().isAfter(c.getDeadline())) throw deny("token outlives the context");
        return chain;
    }

    private List<InvocationContext> chainOf(InvocationContext c) {
        List<InvocationContext> chain = contexts.chain(c.getId(), c.getTenantId());
        if (!chain.isEmpty()) requireChainShape(chain, c.getId());
        return chain;
    }

    /** Self first, each next element the previous one's parent, ending at the root. Anything else fails closed. */
    static void requireChainShape(List<InvocationContext> chain, UUID self) {
        if (!chain.getFirst().getId().equals(self)) throw deny("context chain out of order");
        for (int i = 1; i < chain.size(); i++) {
            if (!chain.get(i).getId().equals(chain.get(i - 1).getParentId())) throw deny("context chain out of order");
        }
        InvocationContext last = chain.getLast();
        if (last.getParentId() != null || !last.getId().equals(chain.getFirst().getRootId())) throw deny("context chain incomplete");
    }

    /** Every immutable establishment fact, compared exactly (resume and idempotent retry). */
    private static boolean sameEstablishment(InvocationContext c, Establishment in, UUID useCase, String rootSession) {
        return c.getBrokerClientId().equals(in.brokerClientId())
                && c.getBrokerId().equals(in.brokerId())
                && c.getSecurityScope().equals(in.securityScope())
                && c.getGatewayRouteId().equals(in.gatewayRouteId())
                && c.getUseCaseApplicationId().equals(useCase)
                && c.getEntryWorkloadId().equals(in.entryWorkloadId())
                && c.getOriginatingSubject().equals(in.subject().getSubject())
                // A missing kind never matches (fail closed); the stored kind is never null.
                && c.getIdentityKind().equals(in.subject().getClaimAsString("identity_kind"))
                && Objects.equals(c.getRootSessionId(), rootSession)
                && in.destinationAudience().equals(c.getDestinationAudience());
    }

    private InvocationContextRaceProbe raceProbe;

    @org.springframework.beans.factory.annotation.Autowired(required = false)
    void setRaceProbe(InvocationContextRaceProbe raceProbe) {
        this.raceProbe = raceProbe;
    }

    private void probe(String point, UUID id) {
        if (raceProbe != null) raceProbe.reached(point, id);
    }

    private void requireUsable(List<InvocationContext> chain, Instant now) {
        if (chain.isEmpty()) throw deny("unknown context");
        for (InvocationContext link : chain) {
            if (link.getStatus() != InvocationContext.Status.ACTIVE) throw deny("context revoked");
        }
        if (!now.isBefore(chain.getFirst().getDeadline())) throw deny("context deadline passed");
    }

    private static String rootSessionOf(Jwt token) {
        String root = token.getClaimAsString("subject_sid");
        return root == null || root.isBlank() ? null : root;
    }

    private static int depthOf(Jwt token) {
        Object raw = token.getClaims().get(CLAIM_DEPTH);
        if (!(raw instanceof Number n) || n.intValue() < 0) throw deny("malformed context depth");
        return n.intValue();
    }

    private String fingerprint(Establishment in, UUID useCase, String rootSession) {
        String canonical = String.join("|", in.tenantId(), in.brokerClientId(), in.brokerId().toString(),
                in.securityScope(), in.gatewayRouteId().toString(), in.subject().getSubject(),
                String.valueOf(in.subject().getClaimAsString("identity_kind")), String.valueOf(rootSession),
                useCase.toString(), in.entryWorkloadId().toString(), in.destinationAudience(),
                String.join(" ", new TreeSet<>(in.requestedScopes())));
        return secrets.keyedDigest("invocation-request", canonical);
    }

    private static Map<String, Object> snapshot(InvocationContext c) {
        Map<String, Object> s = new LinkedHashMap<>();
        s.put("context_id", c.getId().toString());
        s.put("root_id", c.getRootId().toString());
        if (c.getParentId() != null) s.put("parent_id", c.getParentId().toString());
        s.put("version", c.getVersion());
        s.put("status", c.getStatus().name());
        s.put("security_scope", c.getSecurityScope());
        s.put("use_case_application_id", c.getUseCaseApplicationId().toString());
        s.put("entry_workload_id", c.getEntryWorkloadId().toString());
        s.put("subject", c.getOriginatingSubject());
        s.put("broker", c.getBrokerClientId());
        s.put("broker_id", c.getBrokerId().toString());
        s.put("gateway_route_id", c.getGatewayRouteId().toString());
        if (c.getDestinationAudience() != null) s.put("destination_audience", c.getDestinationAudience());
        s.put("authority_ceiling", c.getAuthorityCeiling());
        s.put("deadline", c.getDeadline().toString());
        s.put("max_depth", c.getMaxDepth());
        if (c.getRunRef() != null) s.put("run_ref", c.getRunRef());
        if (c.getBranchRef() != null) s.put("branch_ref", c.getBranchRef());
        if (c.getAuthorizationReference() != null) s.put("authorization_reference", c.getAuthorizationReference());
        return s;
    }

    private static Set<String> scopes(Jwt jwt) {
        Object raw = jwt.getClaims().get("scope");
        Set<String> result = new TreeSet<>();
        if (raw instanceof String value) {
            for (String s : value.trim().split("\\s+")) if (!s.isBlank()) result.add(s);
        } else if (raw instanceof Collection<?> values) {
            values.forEach(v -> result.add(String.valueOf(v)));
        }
        return result;
    }

    private static UUID uuid(String value) {
        try {
            return UUID.fromString(Objects.requireNonNull(value));
        } catch (RuntimeException e) {
            throw deny("malformed context id");
        }
    }

    private static String label(String value) {
        if (value == null) return null;
        String trimmed = value.strip();
        return trimmed.length() > MAX_LABEL ? trimmed.substring(0, MAX_LABEL) : trimmed;
    }

    private static Duration minimum(Duration a, Duration b) { return a.compareTo(b) <= 0 ? a : b; }
    private static Instant earliest(Instant a, Instant b) { return a.isBefore(b) ? a : b; }

    static Denied deny(String reason) { return new Denied(OAuth2ErrorCodes.INVALID_GRANT, reason); }
}
