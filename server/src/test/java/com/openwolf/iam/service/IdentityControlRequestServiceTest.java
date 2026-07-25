package com.openwolf.iam.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.openwolf.iam.auth.ExecutionTenant;
import com.openwolf.iam.dto.IdentityControlProposalRequest;
import com.openwolf.iam.dto.IdentityControlTransitionRequest;
import com.openwolf.iam.entity.IdentityControlRequest;
import com.openwolf.iam.repository.IdentityControlRequestRepository;
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
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class IdentityControlRequestServiceTest {
    private static final String TENANT = "tenant-a";
    private static final Instant NOW = Instant.parse("2026-07-25T12:00:00Z");
    private final IdentityControlRequestRepository requests = mock(IdentityControlRequestRepository.class);
    private final ExecutionTenant executionTenant = mock(ExecutionTenant.class);
    private final AuditService audit = mock(AuditService.class);
    private final SecretProtector secrets = mock(SecretProtector.class);
    private final IdentityControlRequestExpiryService expiry = mock(IdentityControlRequestExpiryService.class);
    private final IdentityControlRequestService service = new IdentityControlRequestService(requests, executionTenant, audit,
            secrets, new ObjectMapper(), expiry, Clock.fixed(NOW, ZoneOffset.UTC), 900);

    @AfterEach
    void clearSecurity() { SecurityContextHolder.clearContext(); }

    @Test
    void enforcesActionTargetMappingAndDistinctApproval() {
        authorize("alice");
        when(secrets.protect(any())).thenAnswer(invocation -> "encrypted:" + invocation.getArgument(0));
        when(requests.save(any())).thenAnswer(invocation -> invocation.getArgument(0));
        when(expiry.expireIfDue(any(), any(), any())).thenReturn(false);
        UUID target = UUID.randomUUID();
        var payload = new ObjectMapper().createObjectNode().put("replacement", "generated-by-apply");
        var created = service.propose(TENANT, new IdentityControlProposalRequest(
                IdentityControlRequest.Action.ROTATE_APPLICATION_CLIENT_SECRET,
                IdentityControlRequest.TargetType.APPLICATION_CLIENT, target, payload, 4L), null);

        assertThat(created.status()).isEqualTo(IdentityControlRequest.Status.PENDING);
        assertThat(created.payloadHash()).hasSize(64);
        assertThat(created.initiatorPrincipalId()).isEqualTo("alice");
        assertThat(created.revision()).isEqualTo(1);
        verify(secrets).protect(any());

        IdentityControlRequest persisted = new IdentityControlRequest(TENANT,
                IdentityControlRequest.Action.ROTATE_APPLICATION_CLIENT_SECRET,
                IdentityControlRequest.TargetType.APPLICATION_CLIENT, target, created.payloadHash(), "ciphertext",
                "alice", NOW, NOW.plusSeconds(900), 4L);
        when(requests.findForUpdateByIdAndTenantId(created.id(), TENANT)).thenReturn(Optional.of(persisted));
        assertThatThrownBy(() -> service.approve(TENANT, created.id(), new IdentityControlTransitionRequest(1L), null))
                .isInstanceOf(com.openwolf.iam.exception.ResourceConflictException.class)
                .hasMessageContaining("initiator");

        authorize("bob");
        assertThat(service.approve(TENANT, created.id(), new IdentityControlTransitionRequest(1L), null).status())
                .isEqualTo(IdentityControlRequest.Status.APPROVED);
        assertThatThrownBy(() -> service.approve(TENANT, created.id(), new IdentityControlTransitionRequest(1L), null))
                .isInstanceOf(com.openwolf.iam.exception.ResourceConflictException.class);
    }

    @Test
    void expiresAndHidesCrossTenantRequests() {
        authorize("bob");
        UUID id = UUID.randomUUID();
        IdentityControlRequest expired = new IdentityControlRequest(TENANT,
                IdentityControlRequest.Action.REVOKE_SCIM_SOURCE,
                IdentityControlRequest.TargetType.SCIM_SOURCE, UUID.randomUUID(), "hash", null,
                "alice", NOW.minusSeconds(901), NOW.minusSeconds(1), 2L);
        when(expiry.expireIfDue(TENANT, id, NOW)).thenReturn(true);
        assertThatThrownBy(() -> service.approve(TENANT, id, new IdentityControlTransitionRequest(1L), null))
                .isInstanceOf(com.openwolf.iam.exception.ResourceConflictException.class)
                .hasMessageContaining("expired");
        assertThat(expired.getStatus()).isEqualTo(IdentityControlRequest.Status.PENDING);

        when(executionTenant.require()).thenReturn("tenant-b");
        assertThatThrownBy(() -> service.get(TENANT, id))
                .isInstanceOf(com.openwolf.iam.exception.EntityNotFoundException.class);
    }

    @Test
    void readUsesUnlockedTenantLookup() {
        authorize("alice");
        UUID id = UUID.randomUUID();
        IdentityControlRequest persisted = new IdentityControlRequest(TENANT,
                IdentityControlRequest.Action.DISABLE_IDENTITY_SOURCE,
                IdentityControlRequest.TargetType.IDENTITY_SOURCE, UUID.randomUUID(), "hash", null,
                "alice", NOW, NOW.plusSeconds(900), 1L);
        when(requests.findForReadByIdAndTenantId(id, TENANT)).thenReturn(Optional.of(persisted));

        assertThat(service.get(TENANT, id).status()).isEqualTo(IdentityControlRequest.Status.PENDING);
        org.mockito.Mockito.verify(requests).findForReadByIdAndTenantId(id, TENANT);
        org.mockito.Mockito.verify(requests, org.mockito.Mockito.never()).findForUpdateByIdAndTenantId(id, TENANT);
    }

    private void authorize(String actor) {
        when(executionTenant.require()).thenReturn(TENANT);
        SecurityContextHolder.getContext().setAuthentication(
                new TestingAuthenticationToken(actor, "", "ROLE_tenant_admin"));
    }
}
