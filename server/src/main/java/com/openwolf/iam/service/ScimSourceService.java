package com.openwolf.iam.service;

import com.openwolf.iam.auth.ExecutionTenant;
import com.openwolf.iam.dto.CreateScimSourceRequest;
import com.openwolf.iam.dto.ScimSourceResponse;
import com.openwolf.iam.entity.ScimProvisioningSource;
import com.openwolf.iam.exception.EntityNotFoundException;
import com.openwolf.iam.exception.ResourceConflictException;
import com.openwolf.iam.repository.IdentitySourceRepository;
import com.openwolf.iam.repository.ScimProvisioningSourceRepository;
import com.openwolf.iam.scim.ScimCredentialService;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.UUID;

@Service
@Transactional
public class ScimSourceService {
    private final ScimProvisioningSourceRepository sources;
    private final IdentitySourceRepository identitySources;
    private final ScimCredentialService credentials;
    private final AuditService audit;
    private final ExecutionTenant tenant;

    public ScimSourceService(ScimProvisioningSourceRepository sources, IdentitySourceRepository identitySources,
                             ScimCredentialService credentials, AuditService audit, ExecutionTenant tenant) {
        this.sources = sources; this.identitySources = identitySources; this.credentials = credentials; this.audit = audit; this.tenant = tenant;
    }
    @Transactional(readOnly = true)
    public List<ScimSourceResponse> list(String tenantId) {
        requireTenant(tenantId); return sources.findByTenantIdOrderByDisplayName(tenantId).stream().map(this::response).toList();
    }
    public ScimSourceResponse create(String tenantId, CreateScimSourceRequest request, HttpServletRequest httpRequest) {
        requireTenant(tenantId);
        if (sources.existsByTenantIdAndDisplayName(tenantId, request.displayName())) throw new ResourceConflictException("SCIM source already exists");
        if (request.identitySourceId() != null && identitySources.findByIdAndTenantId(request.identitySourceId(), tenantId).isEmpty()) throw EntityNotFoundException.forId("Identity source", request.identitySourceId());
        ScimCredentialService.Credential issued = credentials.issue();
        ScimProvisioningSource source = sources.save(new ScimProvisioningSource(tenantId, request.identitySourceId(), request.displayName(), issued.selector(), issued.secretHash()));
        audit.logRequired(tenantId, audit.currentActor(), "CREATE_SCIM_SOURCE", "scim_source", source.getId().toString(), null, response(source), correlation(httpRequest));
        return responseWithSecret(source, issued.bearer());
    }
    public ScimSourceResponse rotate(String tenantId, UUID id, HttpServletRequest httpRequest) {
        ScimProvisioningSource source = source(tenantId, id); ScimCredentialService.Credential issued = credentials.issue();
        source.rotate(issued.selector(), issued.secretHash()); sources.save(source);
        audit.logRequired(tenantId, audit.currentActor(), "ROTATE_SCIM_SOURCE_CREDENTIAL", "scim_source", id.toString(), null, response(source), correlation(httpRequest));
        return responseWithSecret(source, issued.bearer());
    }
    public void revoke(String tenantId, UUID id, HttpServletRequest httpRequest) {
        ScimProvisioningSource source = source(tenantId, id); source.revoke(); sources.save(source);
        audit.logRequired(tenantId, audit.currentActor(), "REVOKE_SCIM_SOURCE", "scim_source", id.toString(), null, response(source), correlation(httpRequest));
    }
    private ScimProvisioningSource source(String tenantId, UUID id) { requireTenant(tenantId); return sources.findByIdAndTenantId(id, tenantId).orElseThrow(() -> EntityNotFoundException.forId("SCIM source", id)); }
    private void requireTenant(String tenantId) { if (!tenant.require().equals(tenantId)) throw EntityNotFoundException.forId("SCIM source", tenantId); }
    private ScimSourceResponse response(ScimProvisioningSource source) { return new ScimSourceResponse(source.getId(), source.getTenantId(), source.getDisplayName(), source.getIdentitySourceId(), source.getSelector(), source.getStatus().name(), source.getRevision(), source.getCreatedAt(), source.getUpdatedAt(), null); }
    private ScimSourceResponse responseWithSecret(ScimProvisioningSource source, String secret) { ScimSourceResponse base = response(source); return new ScimSourceResponse(base.id(), base.tenantId(), base.displayName(), base.identitySourceId(), base.selector(), base.status(), base.revision(), base.createdAt(), base.updatedAt(), secret); }
    private static String correlation(HttpServletRequest request) { return request == null ? null : request.getHeader("X-Correlation-ID"); }
}
