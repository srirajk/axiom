package com.openwolf.iam.service;

import com.openwolf.iam.auth.ExecutionTenant;
import com.openwolf.iam.dto.CreateExternalIdentityLinkRequest;
import com.openwolf.iam.dto.CreateIdentitySourceRequest;
import com.openwolf.iam.dto.ExternalIdentityLinkResponse;
import com.openwolf.iam.dto.IdentitySourceResponse;
import com.openwolf.iam.dto.RotateIdentitySourceSecretRequest;
import com.openwolf.iam.dto.ValidateIdentitySourceResponse;
import com.openwolf.iam.entity.ExternalIdentityLink;
import com.openwolf.iam.entity.IdentitySource;
import com.openwolf.iam.exception.EntityNotFoundException;
import com.openwolf.iam.exception.ResourceConflictException;
import com.openwolf.iam.federation.OidcProviderValidator;
import com.openwolf.iam.repository.ExternalIdentityLinkRepository;
import com.openwolf.iam.repository.IdentitySourceRepository;
import com.openwolf.iam.repository.PrincipalRepository;
import com.openwolf.iam.security.SecretProtector;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

@Service
@Transactional
public class IdentitySourceService {
    private final IdentitySourceRepository sources;
    private final ExternalIdentityLinkRepository links;
    private final PrincipalRepository principals;
    private final OidcProviderValidator validator;
    private final SecretProtector secrets;
    private final AuditService audit;
    private final ExecutionTenant executionTenant;

    public IdentitySourceService(IdentitySourceRepository sources, ExternalIdentityLinkRepository links,
                                 PrincipalRepository principals, OidcProviderValidator validator,
                                 SecretProtector secrets, AuditService audit, ExecutionTenant executionTenant) {
        this.sources = sources; this.links = links; this.principals = principals; this.validator = validator;
        this.secrets = secrets; this.audit = audit; this.executionTenant = executionTenant;
    }

    @Transactional(readOnly = true)
    public List<IdentitySourceResponse> list(String tenantId) { requireTenantAdmin(tenantId); return sources.findByTenantIdOrderByDisplayName(tenantId).stream().map(this::response).toList(); }

    @Transactional(readOnly = true)
    public IdentitySourceResponse get(String tenantId, UUID sourceId) { return response(source(tenantId, sourceId)); }

    public IdentitySourceResponse create(String tenantId, CreateIdentitySourceRequest request, HttpServletRequest httpRequest) {
        requireTenantAdmin(tenantId);
        if (sources.existsByTenantIdAndIssuer(tenantId, request.issuer())) throw new ResourceConflictException("identity source issuer already exists");
        IdentitySource source = sources.save(new IdentitySource(tenantId, request.displayName(), request.issuer(), request.discoveryUri(),
                request.clientId(), secrets.protect(request.clientSecret()), request.requestedScopes(), request.allowedSigningAlgorithms(),
                request.requiredClaims(), request.requiredAcrValues() == null ? List.of() : request.requiredAcrValues()));
        audit.logRequired(tenantId, audit.currentActor(), "CREATE_IDENTITY_SOURCE", "identity_source", source.getId().toString(), null, response(source), correlation(httpRequest));
        return response(source);
    }

    public ValidateIdentitySourceResponse validate(String tenantId, UUID sourceId, HttpServletRequest httpRequest) {
        IdentitySource source = source(tenantId, sourceId);
        CreateIdentitySourceRequest request = new CreateIdentitySourceRequest(source.getDisplayName(), source.getIssuer(), source.getDiscoveryUri(),
                source.getClientId(), secrets.reveal(source.getClientSecretCiphertext()), source.getRequestedScopes(), source.getAllowedSigningAlgorithms(),
                source.getRequiredClaims(), source.getRequiredAcrValues());
        OidcProviderValidator.ValidatedProvider validated = validator.validate(request);
        var metadata = validated.metadata();
        source.applyValidatedMetadata(metadata.authorizationEndpoint().toString(), metadata.tokenEndpoint().toString(),
                metadata.userinfoEndpoint().toString(), metadata.jwksUri().toString(), Instant.now());
        sources.save(source);
        ValidateIdentitySourceResponse result = new ValidateIdentitySourceResponse(metadata.issuer(), metadata.authorizationEndpoint().toString(),
                metadata.tokenEndpoint().toString(), metadata.userinfoEndpoint().toString(), metadata.jwksUri().toString(),
                metadata.idTokenSigningAlgorithms(), metadata.claims(), metadata.acrValues());
        audit.logRequired(tenantId, audit.currentActor(), "VALIDATE_IDENTITY_SOURCE", "identity_source", sourceId.toString(), null, result, correlation(httpRequest));
        return result;
    }

    public IdentitySourceResponse activate(String tenantId, UUID sourceId, HttpServletRequest httpRequest) {
        IdentitySource source = source(tenantId, sourceId);
        if (source.getStatus() != IdentitySource.Status.VALIDATED) throw new ResourceConflictException("identity source must be validated before activation");
        source.activate(); sources.save(source);
        audit.logRequired(tenantId, audit.currentActor(), "ACTIVATE_IDENTITY_SOURCE", "identity_source", sourceId.toString(), null, response(source), correlation(httpRequest));
        return response(source);
    }

    public void disable(String tenantId, UUID sourceId, HttpServletRequest httpRequest) {
        IdentitySource source = source(tenantId, sourceId); source.disable(); sources.save(source);
        audit.logRequired(tenantId, audit.currentActor(), "DISABLE_IDENTITY_SOURCE", "identity_source", sourceId.toString(), null, response(source), correlation(httpRequest));
    }

    public void rotateSecret(String tenantId, UUID sourceId, RotateIdentitySourceSecretRequest request, HttpServletRequest httpRequest) {
        IdentitySource source = source(tenantId, sourceId); source.rotateSecret(secrets.protect(request.clientSecret())); sources.save(source);
        audit.logRequired(tenantId, audit.currentActor(), "ROTATE_IDENTITY_SOURCE_SECRET", "identity_source", sourceId.toString(), null,
                java.util.Map.of("status", "rotated"), correlation(httpRequest));
    }

    @Transactional(readOnly = true)
    public List<ExternalIdentityLinkResponse> listLinks(String tenantId, UUID sourceId) {
        source(tenantId, sourceId); return links.findByTenantIdAndSourceIdOrderBySubject(tenantId, sourceId).stream().map(this::linkResponse).toList();
    }

    public ExternalIdentityLinkResponse link(String tenantId, UUID sourceId, CreateExternalIdentityLinkRequest request, HttpServletRequest httpRequest) {
        IdentitySource source = source(tenantId, sourceId);
        if (source.getStatus() != IdentitySource.Status.ACTIVE) throw new ResourceConflictException("identity source is not active");
        if (!source.getId().equals(request.sourceId()) || !source.getIssuer().equals(request.issuer())) throw new IllegalArgumentException("source and issuer must match exactly");
        if (principals.findByIdAndTenantId(request.principalId(), tenantId).isEmpty()) throw EntityNotFoundException.forId("Principal", request.principalId());
        if (links.existsBySourceIdAndIssuerAndSubject(sourceId, request.issuer(), request.subject())) throw new ResourceConflictException("external identity link already exists");
        if (links.existsBySourceIdAndPrincipalId(sourceId, request.principalId())) throw new ResourceConflictException("principal is already linked to this identity source");
        ExternalIdentityLink link = links.save(new ExternalIdentityLink(tenantId, sourceId, request.issuer(), request.subject(), request.principalId()));
        audit.logRequired(tenantId, audit.currentActor(), "LINK_EXTERNAL_IDENTITY", "external_identity_link", link.getId().toString(), null, linkResponse(link), correlation(httpRequest));
        return linkResponse(link);
    }

    public void disableLink(String tenantId, UUID sourceId, UUID linkId, HttpServletRequest httpRequest) {
        source(tenantId, sourceId); ExternalIdentityLink link = links.findByIdAndTenantId(linkId, tenantId).orElseThrow(() -> EntityNotFoundException.forId("External identity link", linkId));
        if (!sourceId.equals(link.getSourceId())) throw EntityNotFoundException.forId("External identity link", linkId);
        link.disable(); links.save(link); audit.logRequired(tenantId, audit.currentActor(), "DISABLE_EXTERNAL_IDENTITY_LINK", "external_identity_link", linkId.toString(), null, linkResponse(link), correlation(httpRequest));
    }

    private IdentitySource source(String tenantId, UUID id) {
        requireTenantAdmin(tenantId); return sources.findByIdAndTenantId(id, tenantId).orElseThrow(() -> EntityNotFoundException.forId("Identity source", id));
    }
    private void requireTenantAdmin(String tenantId) {
        if (!executionTenant.require().equals(tenantId)) throw EntityNotFoundException.forId("Identity source", tenantId);
    }
    private IdentitySourceResponse response(IdentitySource source) { return new IdentitySourceResponse(source.getId(), source.getTenantId(), source.getDisplayName(), source.getIssuer(), source.getDiscoveryUri(), source.getAuthorizationEndpoint(), source.getTokenEndpoint(), source.getUserinfoEndpoint(), source.getJwksUri(), source.getClientId(), source.getRequestedScopes(), source.getAllowedSigningAlgorithms(), source.getRequiredClaims(), source.getRequiredAcrValues(), source.getStatus(), source.getRevision(), source.getLastValidatedAt(), source.getCreatedAt(), source.getUpdatedAt()); }
    private ExternalIdentityLinkResponse linkResponse(ExternalIdentityLink link) { return new ExternalIdentityLinkResponse(link.getId(), link.getSourceId(), link.getIssuer(), link.getSubject(), link.getPrincipalId(), link.getStatus(), link.getCreatedAt(), link.getUpdatedAt()); }
    private static String correlation(HttpServletRequest request) { return request == null ? null : request.getHeader("X-Correlation-ID"); }
}
