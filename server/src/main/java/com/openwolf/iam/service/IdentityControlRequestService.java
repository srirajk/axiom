package com.openwolf.iam.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.openwolf.iam.auth.ExecutionTenant;
import com.openwolf.iam.dto.IdentityControlProposalRequest;
import com.openwolf.iam.dto.IdentityControlRequestResponse;
import com.openwolf.iam.dto.IdentityControlTransitionRequest;
import com.openwolf.iam.entity.IdentityControlRequest;
import com.openwolf.iam.exception.EntityNotFoundException;
import com.openwolf.iam.exception.ResourceConflictException;
import com.openwolf.iam.repository.IdentityControlRequestRepository;
import com.openwolf.iam.security.SecretProtector;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Clock;
import java.time.Instant;
import java.util.TreeMap;
import java.util.UUID;

@Service
@Transactional
public class IdentityControlRequestService {
    private final IdentityControlRequestRepository requests;
    private final ExecutionTenant executionTenant;
    private final AuditService audit;
    private final SecretProtector secrets;
    private final ObjectMapper mapper;
    private final Clock clock;
    private final long ttlSeconds;
    private final IdentityControlRequestExpiryService expiry;

    @Autowired
    public IdentityControlRequestService(IdentityControlRequestRepository requests, ExecutionTenant executionTenant,
                                         AuditService audit, SecretProtector secrets, ObjectMapper mapper,
                                         IdentityControlRequestExpiryService expiry,
                                         @Value("${iam.identity-control.request-ttl-seconds:900}") long ttlSeconds) {
        this(requests, executionTenant, audit, secrets, mapper, expiry, Clock.systemUTC(), ttlSeconds);
    }

    IdentityControlRequestService(IdentityControlRequestRepository requests, ExecutionTenant executionTenant,
                                  AuditService audit, SecretProtector secrets, ObjectMapper mapper,
                                  IdentityControlRequestExpiryService expiry,
                                  Clock clock, long ttlSeconds) {
        this.requests = requests; this.executionTenant = executionTenant; this.audit = audit; this.secrets = secrets;
        this.mapper = mapper; this.clock = clock; this.ttlSeconds = ttlSeconds; this.expiry = expiry;
    }

    public IdentityControlRequestResponse propose(String tenantId, @Valid IdentityControlProposalRequest input,
                                                  HttpServletRequest httpRequest) {
        requireTenantAdmin(tenantId);
        validateTarget(input.action(), input.targetType());
        String canonical = canonical(input.payload());
        IdentityControlRequest request = requests.save(new IdentityControlRequest(tenantId, input.action(), input.targetType(),
                input.targetId(), sha256(canonical), canonical.equals("{}") ? null : secrets.protect(canonical),
                currentActor(), clock.instant(), clock.instant().plusSeconds(ttlSeconds), input.expectedTargetRevision()));
        IdentityControlRequestResponse result = response(request);
        auditTransition(tenantId, request, "PROPOSE_IDENTITY_CONTROL_REQUEST", null, result, httpRequest);
        return result;
    }

    @Transactional(readOnly = true)
    public Page<IdentityControlRequestResponse> list(String tenantId, IdentityControlRequest.Status status,
                                                     int page, int size) {
        requireTenantAdmin(tenantId);
        return requests.search(tenantId, status, PageRequest.of(Math.max(page, 0), Math.min(Math.max(size, 1), 100)))
                .map(this::response);
    }

    @Transactional(readOnly = true)
    public IdentityControlRequestResponse get(String tenantId, UUID id) {
        requireTenantAdmin(tenantId);
        return response(findForRead(tenantId, id));
    }

    public IdentityControlRequestResponse approve(String tenantId, UUID id, IdentityControlTransitionRequest input,
                                                  HttpServletRequest httpRequest) {
        ensureLive(tenantId, id);
        IdentityControlRequest request = transitionTarget(tenantId, id, input.expectedRevision());
        if (request.getInitiatorPrincipalId().equals(currentActor())) throw new ResourceConflictException("initiator cannot approve its own request");
        if (request.getStatus() != IdentityControlRequest.Status.PENDING) throw terminal(request);
        String actor = currentActor(); request.approve(actor, clock.instant()); requests.save(request);
        IdentityControlRequestResponse result = response(request, request.getRevision() + 1);
        auditTransition(tenantId, request, "APPROVE_IDENTITY_CONTROL_REQUEST", null, result, httpRequest);
        return result;
    }

    public IdentityControlRequestResponse reject(String tenantId, UUID id, IdentityControlTransitionRequest input,
                                                 HttpServletRequest httpRequest) {
        ensureLive(tenantId, id);
        IdentityControlRequest request = transitionTarget(tenantId, id, input.expectedRevision());
        if (request.getInitiatorPrincipalId().equals(currentActor())) throw new ResourceConflictException("initiator cannot reject its own request");
        if (request.getStatus() != IdentityControlRequest.Status.PENDING) throw terminal(request);
        request.reject(); requests.save(request);
        IdentityControlRequestResponse result = response(request, request.getRevision() + 1);
        auditTransition(tenantId, request, "REJECT_IDENTITY_CONTROL_REQUEST", null, result, httpRequest);
        return result;
    }

    public IdentityControlRequestResponse cancel(String tenantId, UUID id, IdentityControlTransitionRequest input,
                                                 HttpServletRequest httpRequest) {
        ensureLive(tenantId, id);
        IdentityControlRequest request = transitionTarget(tenantId, id, input.expectedRevision());
        if (!request.getInitiatorPrincipalId().equals(currentActor()) && !isPlatformAdmin()) {
            throw new EntityNotFoundException("Identity control request not found");
        }
        if (request.getStatus() != IdentityControlRequest.Status.PENDING
                && request.getStatus() != IdentityControlRequest.Status.APPROVED) throw terminal(request);
        request.cancel(); requests.save(request);
        IdentityControlRequestResponse result = response(request, request.getRevision() + 1);
        auditTransition(tenantId, request, "CANCEL_IDENTITY_CONTROL_REQUEST", null, result, httpRequest);
        return result;
    }

    private IdentityControlRequest transitionTarget(String tenantId, UUID id, long expectedRevision) {
        requireTenantAdmin(tenantId); IdentityControlRequest request = findForUpdate(tenantId, id);
        if (request.getRevision() != expectedRevision) throw new ResourceConflictException("identity control request revision is stale");
        return request;
    }

    private IdentityControlRequest findForRead(String tenantId, UUID id) {
        return requests.findForReadByIdAndTenantId(id, tenantId)
                .orElseThrow(() -> EntityNotFoundException.forId("Identity control request", id));
    }

    private IdentityControlRequest findForUpdate(String tenantId, UUID id) {
        return requests.findForUpdateByIdAndTenantId(id, tenantId)
                .orElseThrow(() -> EntityNotFoundException.forId("Identity control request", id));
    }

    private void ensureLive(String tenantId, UUID id) {
        if (expiry.expireIfDue(tenantId, id, clock.instant())) {
            throw new ResourceConflictException("identity control request has expired");
        }
    }

    private ResourceConflictException terminal(IdentityControlRequest request) {
        return new ResourceConflictException("identity control request is not transitionable from " + request.getStatus());
    }

    private void validateTarget(IdentityControlRequest.Action action, IdentityControlRequest.TargetType target) {
        IdentityControlRequest.TargetType expected = switch (action) {
            case EMERGENCY_RETIRE_SIGNING_KEY -> IdentityControlRequest.TargetType.SIGNING_KEY;
            case DISABLE_IDENTITY_SOURCE, ROTATE_IDENTITY_SOURCE_SECRET -> IdentityControlRequest.TargetType.IDENTITY_SOURCE;
            case REVOKE_APPLICATION_CLIENT_SECRET, ROTATE_APPLICATION_CLIENT_SECRET -> IdentityControlRequest.TargetType.APPLICATION_CLIENT;
            case REVOKE_SCIM_SOURCE, ROTATE_SCIM_SOURCE_CREDENTIAL -> IdentityControlRequest.TargetType.SCIM_SOURCE;
        };
        if (expected != target) throw new ResourceConflictException("identity control action and target type do not match");
    }

    private void requireTenantAdmin(String tenantId) {
        if (tenantId.equals(executionTenant.require()) || isPlatformAdmin()) return;
        throw new EntityNotFoundException("Identity control request not found");
    }

    private boolean isPlatformAdmin() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        return auth != null && auth.getAuthorities().stream().anyMatch(a -> "ROLE_platform_admin".equals(a.getAuthority()));
    }

    private String currentActor() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth == null || !auth.isAuthenticated()) throw new IllegalStateException("authenticated initiator is required");
        if (auth.getPrincipal() instanceof Jwt jwt && jwt.getSubject() != null) return jwt.getSubject();
        return auth.getName();
    }

    private String canonical(JsonNode payload) {
        try { return mapper.writeValueAsString(sort(payload == null || payload.isNull() ? mapper.createObjectNode() : payload)); }
        catch (Exception ex) { throw new ResourceConflictException("identity control payload is not canonicalizable", ex); }
    }

    private JsonNode sort(JsonNode value) {
        if (value.isObject()) {
            ObjectNode out = mapper.createObjectNode();
            TreeMap<String, JsonNode> fields = new TreeMap<>();
            value.fields().forEachRemaining(e -> fields.put(e.getKey(), e.getValue()));
            fields.forEach((key, child) -> out.set(key, sort(child)));
            return out;
        }
        if (value.isArray()) { ArrayNode out = mapper.createArrayNode(); value.forEach(v -> out.add(sort(v))); return out; }
        return value;
    }

    private static String sha256(String value) {
        try { return java.util.HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8))); }
        catch (Exception ex) { throw new IllegalStateException("SHA-256 unavailable", ex); }
    }

    private IdentityControlRequestResponse response(IdentityControlRequest request) { return response(request, request.getRevision()); }
    private IdentityControlRequestResponse response(IdentityControlRequest r, long revision) {
        return new IdentityControlRequestResponse(r.getId(), r.getTenantId(), r.getAction(), r.getTargetType(), r.getTargetId(),
                r.getPayloadHash(), r.getInitiatorPrincipalId(), r.getCreatedAt(), r.getExpiresAt(), r.getExpectedTargetRevision(),
                r.getStatus(), r.getApproverPrincipalId(), r.getApprovedAt(), r.getApplicationResultReference(), revision);
    }

    private void auditTransition(String tenantId, IdentityControlRequest request, String action, Object before, Object after,
                                 HttpServletRequest httpRequest) {
        audit.logRequired(tenantId, audit.currentActor(), action, "identity_control_request", request.getId().toString(), before, after,
                httpRequest == null ? null : httpRequest.getHeader("X-Correlation-ID"));
    }
}
