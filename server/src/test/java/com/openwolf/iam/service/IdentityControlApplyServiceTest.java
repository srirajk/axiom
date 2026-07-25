package com.openwolf.iam.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.openwolf.iam.auth.ExecutionTenant;
import com.openwolf.iam.entity.IdentityControlRequest;
import com.openwolf.iam.repository.IdentityControlRequestRepository;
import com.openwolf.iam.repository.IdentitySourceRepository;
import com.openwolf.iam.repository.ScimProvisioningSourceRepository;
import com.openwolf.iam.repository.SigningKeyRepository;
import com.openwolf.iam.repository.TenantApplicationClientRepository;
import com.openwolf.iam.repository.TenantApplicationRepository;
import com.openwolf.iam.security.SecretProtector;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class IdentityControlApplyServiceTest {
    private static final String TENANT = "tenant-a";
    private static final Instant NOW = Instant.parse("2026-07-25T12:00:00Z");
    private final IdentityControlRequestRepository requests = mock(IdentityControlRequestRepository.class);
    private final IdentityControlRequestExpiryService expiry = mock(IdentityControlRequestExpiryService.class);
    private final IdentitySourceRepository identitySources = mock(IdentitySourceRepository.class);
    private final ScimProvisioningSourceRepository scimSources = mock(ScimProvisioningSourceRepository.class);
    private final SigningKeyRepository signingKeys = mock(SigningKeyRepository.class);
    private final TenantApplicationClientRepository clients = mock(TenantApplicationClientRepository.class);
    private final TenantApplicationRepository applications = mock(TenantApplicationRepository.class);
    private final IdentitySourceService identitySourceService = mock(IdentitySourceService.class);
    private final ScimSourceService scimSourceService = mock(ScimSourceService.class);
    private final SigningKeyLifecycleService signingKeyService = mock(SigningKeyLifecycleService.class);
    private final TenantApplicationService applicationService = mock(TenantApplicationService.class);
    private final ExecutionTenant executionTenant = mock(ExecutionTenant.class);
    private final AuditService audit = mock(AuditService.class);
    private final SecretProtector secrets = mock(SecretProtector.class);
    private final IdentityControlApplyService service = new IdentityControlApplyService(requests, expiry, identitySources,
            scimSources, signingKeys, clients, applications, identitySourceService, scimSourceService,
            signingKeyService, applicationService, executionTenant, audit, secrets, new ObjectMapper(),
            Clock.fixed(NOW, ZoneOffset.UTC));

    @AfterEach
    void clearSecurity() { SecurityContextHolder.clearContext(); }

    @Test
    void appliedRetryReturnsStoredReferenceWithoutRepeatingMutationOrSecret() {
        UUID id = UUID.randomUUID();
        IdentityControlRequest request = new IdentityControlRequest(TENANT,
                IdentityControlRequest.Action.ROTATE_APPLICATION_CLIENT_SECRET,
                IdentityControlRequest.TargetType.APPLICATION_CLIENT, UUID.randomUUID(),
                sha256("{}"), null, "alice", NOW, NOW.plusSeconds(900), 3L);
        request.approve("bob", NOW);
        request.apply("rotate_application_client_secret:" + request.getTargetId());
        authorizeTenant();
        when(expiry.expireIfDue(TENANT, id, NOW)).thenReturn(false);
        when(requests.findForUpdateByIdAndTenantId(id, TENANT)).thenReturn(Optional.of(request));

        var result = service.apply(TENANT, id, request.getRevision(), null);

        assertThat(result.oneTimeSecret()).isNull();
        assertThat(result.resultReference()).isEqualTo(request.getApplicationResultReference());
        verify(applicationService, never()).rotateClientSecret(org.mockito.ArgumentMatchers.any(),
                org.mockito.ArgumentMatchers.any(), org.mockito.ArgumentMatchers.any(),
                org.mockito.ArgumentMatchers.any(), org.mockito.ArgumentMatchers.any());
        verify(audit, never()).logRequired(org.mockito.ArgumentMatchers.any(), org.mockito.ArgumentMatchers.any(),
                org.mockito.ArgumentMatchers.eq("APPLY_IDENTITY_CONTROL_REQUEST"), org.mockito.ArgumentMatchers.any(),
                org.mockito.ArgumentMatchers.any(), org.mockito.ArgumentMatchers.any(), org.mockito.ArgumentMatchers.any(),
                org.mockito.ArgumentMatchers.any());
    }

    @Test
    void staleRequestRevisionFailsBeforeTargetMutation() {
        UUID id = UUID.randomUUID();
        IdentityControlRequest request = new IdentityControlRequest(TENANT,
                IdentityControlRequest.Action.REVOKE_SCIM_SOURCE,
                IdentityControlRequest.TargetType.SCIM_SOURCE, UUID.randomUUID(),
                sha256("{}"), null, "alice", NOW, NOW.plusSeconds(900), 3L);
        request.approve("bob", NOW);
        authorizeTenant();
        when(expiry.expireIfDue(TENANT, id, NOW)).thenReturn(false);
        when(requests.findForUpdateByIdAndTenantId(id, TENANT)).thenReturn(Optional.of(request));

        assertThatThrownBy(() -> service.apply(TENANT, id, request.getRevision() - 1, null))
                .isInstanceOf(com.openwolf.iam.exception.ResourceConflictException.class)
                .hasMessageContaining("revision is stale");
        verify(scimSourceService, never()).revoke(org.mockito.ArgumentMatchers.any(),
                org.mockito.ArgumentMatchers.any(), org.mockito.ArgumentMatchers.any());
    }

    private void authorizeTenant() {
        when(executionTenant.require()).thenReturn(TENANT);
        SecurityContextHolder.getContext().setAuthentication(
                new TestingAuthenticationToken("approver", "", "ROLE_tenant_admin"));
    }

    private static String sha256(String value) {
        try {
            return java.util.HexFormat.of().formatHex(java.security.MessageDigest.getInstance("SHA-256")
                    .digest(value.getBytes(java.nio.charset.StandardCharsets.UTF_8)));
        } catch (Exception ex) {
            throw new AssertionError(ex);
        }
    }
}
