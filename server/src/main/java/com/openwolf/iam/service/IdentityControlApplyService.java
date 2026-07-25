package com.openwolf.iam.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.openwolf.iam.auth.ExecutionTenant;
import com.openwolf.iam.dto.CreatedTenantApplicationClientResponse;
import com.openwolf.iam.dto.IdentityControlApplyResponse;
import com.openwolf.iam.dto.IdentityControlRequestResponse;
import com.openwolf.iam.dto.RevokeTenantApplicationClientRequest;
import com.openwolf.iam.dto.RotateIdentitySourceSecretRequest;
import com.openwolf.iam.dto.RotateTenantApplicationClientSecretRequest;
import com.openwolf.iam.entity.IdentityControlRequest;
import com.openwolf.iam.entity.IdentitySource;
import com.openwolf.iam.entity.ScimProvisioningSource;
import com.openwolf.iam.entity.SigningKey;
import com.openwolf.iam.entity.TenantApplication;
import com.openwolf.iam.entity.TenantApplicationClient;
import com.openwolf.iam.exception.EntityNotFoundException;
import com.openwolf.iam.exception.ResourceConflictException;
import com.openwolf.iam.repository.IdentityControlRequestRepository;
import com.openwolf.iam.repository.IdentitySourceRepository;
import com.openwolf.iam.repository.ScimProvisioningSourceRepository;
import com.openwolf.iam.repository.SigningKeyRepository;
import com.openwolf.iam.repository.TenantApplicationClientRepository;
import com.openwolf.iam.repository.TenantApplicationRepository;
import com.openwolf.iam.security.SecretProtector;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

import java.time.Clock;
import java.time.Instant;
import java.util.TreeMap;
import java.util.UUID;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

@Service
@Transactional
public class IdentityControlApplyService {
    private final IdentityControlRequestRepository requests;
    private final IdentityControlRequestExpiryService expiry;
    private final IdentitySourceRepository identitySourceRepository;
    private final ScimProvisioningSourceRepository scimRepository;
    private final SigningKeyRepository signingKeyRepository;
    private final TenantApplicationClientRepository clientRepository;
    private final TenantApplicationRepository applicationRepository;
    private final IdentitySourceService identitySources;
    private final ScimSourceService scimSources;
    private final SigningKeyLifecycleService signingKeys;
    private final TenantApplicationService applications;
    private final ExecutionTenant executionTenant;
    private final AuditService audit;
    private final SecretProtector secrets;
    private final ObjectMapper mapper;
    private final Clock clock;

    @Autowired
    public IdentityControlApplyService(IdentityControlRequestRepository requests,
                                       IdentityControlRequestExpiryService expiry,
                                       IdentitySourceRepository identitySourceRepository,
                                       ScimProvisioningSourceRepository scimRepository,
                                       SigningKeyRepository signingKeyRepository,
                                       TenantApplicationClientRepository clientRepository,
                                       TenantApplicationRepository applicationRepository,
                                       IdentitySourceService identitySources, ScimSourceService scimSources,
                                       SigningKeyLifecycleService signingKeys, TenantApplicationService applications,
                                       ExecutionTenant executionTenant, AuditService audit, SecretProtector secrets,
                                       ObjectMapper mapper) {
        this(requests, expiry, identitySourceRepository, scimRepository, signingKeyRepository, clientRepository,
                applicationRepository, identitySources, scimSources, signingKeys, applications, executionTenant,
                audit, secrets, mapper, Clock.systemUTC());
    }

    IdentityControlApplyService(IdentityControlRequestRepository requests, IdentityControlRequestExpiryService expiry,
                                IdentitySourceRepository identitySourceRepository, ScimProvisioningSourceRepository scimRepository,
                                SigningKeyRepository signingKeyRepository, TenantApplicationClientRepository clientRepository,
                                TenantApplicationRepository applicationRepository, IdentitySourceService identitySources,
                                ScimSourceService scimSources, SigningKeyLifecycleService signingKeys,
                                TenantApplicationService applications, ExecutionTenant executionTenant, AuditService audit,
                                SecretProtector secrets, ObjectMapper mapper, Clock clock) {
        this.requests = requests; this.expiry = expiry; this.identitySourceRepository = identitySourceRepository;
        this.scimRepository = scimRepository; this.signingKeyRepository = signingKeyRepository; this.clientRepository = clientRepository;
        this.applicationRepository = applicationRepository; this.identitySources = identitySources; this.scimSources = scimSources;
        this.signingKeys = signingKeys; this.applications = applications; this.executionTenant = executionTenant;
        this.audit = audit; this.secrets = secrets; this.mapper = mapper; this.clock = clock;
    }

    public IdentityControlApplyResponse apply(String tenantId, UUID id, long expectedRevision,
                                              HttpServletRequest httpRequest) {
        requireTenantAdmin(tenantId);
        if (expiry.expireIfDue(tenantId, id, clock.instant())) {
            throw new ResourceConflictException("identity control request has expired");
        }
        IdentityControlRequest request = requests.findForUpdateByIdAndTenantId(id, tenantId)
                .orElseThrow(() -> EntityNotFoundException.forId("Identity control request", id));
        if (request.getStatus() == IdentityControlRequest.Status.APPLIED) {
            return new IdentityControlApplyResponse(response(request), request.getApplicationResultReference(), null);
        }
        if (request.getRevision() != expectedRevision) throw new ResourceConflictException("identity control request revision is stale");
        if (request.getStatus() != IdentityControlRequest.Status.APPROVED) {
            throw new ResourceConflictException("identity control request is not approved");
        }
        validateTarget(request.getAction(), request.getTargetType());
        JsonNode payload = validatedPayload(request);
        long targetRevision;
        String oneTimeSecret = null;
        switch (request.getAction()) {
            case EMERGENCY_RETIRE_SIGNING_KEY -> {
                SigningKey key = signingKeyRepository.findByIdForUpdate(request.getTargetId())
                        .orElseThrow(() -> EntityNotFoundException.forId("Signing key", request.getTargetId()));
                targetRevision = key.getRevision(); verifyTargetRevision(request, targetRevision); requireEmptyPayload(payload);
                signingKeys.emergencyRetire(tenantId, request.getTargetId(), httpRequest);
            }
            case DISABLE_IDENTITY_SOURCE -> {
                IdentitySource source = identitySourceRepository.findByIdAndTenantIdForUpdate(request.getTargetId(), tenantId)
                        .orElseThrow(() -> EntityNotFoundException.forId("Identity source", request.getTargetId()));
                targetRevision = source.getRevision(); verifyTargetRevision(request, targetRevision); requireEmptyPayload(payload);
                identitySources.disable(tenantId, request.getTargetId(), httpRequest);
            }
            case ROTATE_IDENTITY_SOURCE_SECRET -> {
                IdentitySource source = identitySourceRepository.findByIdAndTenantIdForUpdate(request.getTargetId(), tenantId)
                        .orElseThrow(() -> EntityNotFoundException.forId("Identity source", request.getTargetId()));
                targetRevision = source.getRevision(); verifyTargetRevision(request, targetRevision);
                identitySources.rotateSecret(tenantId, request.getTargetId(), new RotateIdentitySourceSecretRequest(requiredSecret(payload)), httpRequest);
            }
            case REVOKE_APPLICATION_CLIENT_SECRET -> {
                TenantApplicationClient client = lockedClient(tenantId, request.getTargetId());
                targetRevision = client.getRevision(); verifyTargetRevision(request, targetRevision); requireEmptyPayload(payload);
                applications.revokeClientSecret(tenantId, client.getApplicationId(), client.getId(),
                        new RevokeTenantApplicationClientRequest(targetRevision), httpRequest);
            }
            case ROTATE_APPLICATION_CLIENT_SECRET -> {
                TenantApplicationClient client = lockedClient(tenantId, request.getTargetId());
                targetRevision = client.getRevision(); verifyTargetRevision(request, targetRevision); requireEmptyPayload(payload);
                CreatedTenantApplicationClientResponse result = applications.rotateClientSecret(tenantId, client.getApplicationId(), client.getId(),
                        new RotateTenantApplicationClientSecretRequest(targetRevision), httpRequest);
                oneTimeSecret = result.serviceSecret();
            }
            case REVOKE_SCIM_SOURCE -> {
                ScimProvisioningSource source = scimRepository.findByIdAndTenantIdForUpdate(request.getTargetId(), tenantId)
                        .orElseThrow(() -> EntityNotFoundException.forId("SCIM source", request.getTargetId()));
                targetRevision = source.getRevision(); verifyTargetRevision(request, targetRevision); requireEmptyPayload(payload);
                scimSources.revoke(tenantId, request.getTargetId(), httpRequest);
            }
            case ROTATE_SCIM_SOURCE_CREDENTIAL -> {
                ScimProvisioningSource source = scimRepository.findByIdAndTenantIdForUpdate(request.getTargetId(), tenantId)
                        .orElseThrow(() -> EntityNotFoundException.forId("SCIM source", request.getTargetId()));
                targetRevision = source.getRevision(); verifyTargetRevision(request, targetRevision); requireEmptyPayload(payload);
                oneTimeSecret = scimSources.rotate(tenantId, request.getTargetId(), httpRequest).bearerCredential();
            }
        }
        String resultReference = request.getAction().name().toLowerCase() + ":" + request.getTargetId();
        request.apply(resultReference); requests.save(request);
        IdentityControlRequestResponse applied = response(request, request.getRevision() + 1);
        audit.logRequired(tenantId, audit.currentActor(), "APPLY_IDENTITY_CONTROL_REQUEST", "identity_control_request",
                request.getId().toString(), null, applied, correlation(httpRequest));
        return new IdentityControlApplyResponse(applied, resultReference, oneTimeSecret);
    }

    private TenantApplicationClient lockedClient(String tenantId, UUID id) {
        TenantApplicationClient client = clientRepository.findByIdForUpdate(id)
                .orElseThrow(() -> EntityNotFoundException.forId("Application client", id));
        TenantApplication app = applicationRepository.findById(client.getApplicationId())
                .filter(a -> tenantId.equals(a.getTenantId()))
                .orElseThrow(() -> EntityNotFoundException.forId("Application client", id));
        if (app.getStatus() != TenantApplication.Status.ACTIVE) throw new ResourceConflictException("Application is disabled");
        return client;
    }

    private JsonNode validatedPayload(IdentityControlRequest request) {
        String canonical = "{}";
        if (request.getPayloadCiphertext() != null) {
            try { canonical = canonical(mapper.readTree(secrets.reveal(request.getPayloadCiphertext()))); }
            catch (Exception ex) { throw new ResourceConflictException("identity control payload cannot be decrypted", ex); }
        }
        if (!sha256(canonical).equals(request.getPayloadHash())) throw new ResourceConflictException("identity control payload hash mismatch");
        try { return mapper.readTree(canonical); } catch (Exception ex) { throw new ResourceConflictException("identity control payload is malformed", ex); }
    }

    private String canonical(JsonNode payload) throws Exception { return mapper.writeValueAsString(sort(payload)); }
    private JsonNode sort(JsonNode value) {
        if (value == null || value.isNull()) return mapper.createObjectNode();
        if (value.isObject()) {
            ObjectNode out = mapper.createObjectNode();
            TreeMap<String, JsonNode> fields = new TreeMap<>();
            value.fields().forEachRemaining(entry -> fields.put(entry.getKey(), entry.getValue()));
            fields.forEach((key, child) -> out.set(key, sort(child)));
            return out;
        }
        if (value.isArray()) {
            ArrayNode out = mapper.createArrayNode();
            value.forEach(child -> out.add(sort(child)));
            return out;
        }
        return value;
    }
    private String requiredSecret(JsonNode payload) {
        JsonNode value = payload.get("clientSecret");
        if (value == null || !value.isTextual() || value.asText().isBlank()) throw new ResourceConflictException("encrypted replacement secret is required");
        return value.asText();
    }
    private void requireEmptyPayload(JsonNode payload) {
        if (payload != null && (!payload.isObject() || payload.size() != 0)) {
            throw new ResourceConflictException("payload is not permitted for this generated mutation");
        }
    }
    private void verifyTargetRevision(IdentityControlRequest request, long actual) {
        if (request.getExpectedTargetRevision() == null || request.getExpectedTargetRevision() != actual) throw new ResourceConflictException("target revision is stale or missing");
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
        throw EntityNotFoundException.forId("Identity control request", tenantId);
    }
    private boolean isPlatformAdmin() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        return authentication != null && authentication.getAuthorities().stream()
                .anyMatch(authority -> "ROLE_platform_admin".equals(authority.getAuthority()));
    }
    private static String sha256(String value) { try { return java.util.HexFormat.of().formatHex(java.security.MessageDigest.getInstance("SHA-256").digest(value.getBytes(java.nio.charset.StandardCharsets.UTF_8))); } catch (Exception ex) { throw new IllegalStateException("SHA-256 unavailable", ex); } }
    private IdentityControlRequestResponse response(IdentityControlRequest request) { return response(request, request.getRevision()); }
    private IdentityControlRequestResponse response(IdentityControlRequest r, long revision) { return new IdentityControlRequestResponse(r.getId(), r.getTenantId(), r.getAction(), r.getTargetType(), r.getTargetId(), r.getPayloadHash(), r.getInitiatorPrincipalId(), r.getCreatedAt(), r.getExpiresAt(), r.getExpectedTargetRevision(), r.getStatus(), r.getApproverPrincipalId(), r.getApprovedAt(), r.getApplicationResultReference(), revision); }
    private static String correlation(HttpServletRequest request) { return request == null ? null : request.getHeader("X-Correlation-ID"); }
}
