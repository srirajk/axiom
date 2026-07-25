package com.openwolf.iam.service;

import com.openwolf.iam.entity.IdentityControlRequest;
import com.openwolf.iam.repository.IdentityControlRequestRepository;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class IdentityControlRequestExpiryServiceTest {
    @Test
    void commitsOnlyOneDueExpiryAndAuditsIt() {
        IdentityControlRequestRepository requests = mock(IdentityControlRequestRepository.class);
        AuditService audit = mock(AuditService.class);
        IdentityControlRequestExpiryService expiry = new IdentityControlRequestExpiryService(requests, audit);
        UUID id = UUID.randomUUID();
        IdentityControlRequest request = new IdentityControlRequest("tenant-a",
                IdentityControlRequest.Action.REVOKE_SCIM_SOURCE,
                IdentityControlRequest.TargetType.SCIM_SOURCE, UUID.randomUUID(), "hash", null,
                "alice", Instant.parse("2026-07-25T11:00:00Z"), Instant.parse("2026-07-25T11:59:00Z"), 1L);
        when(requests.findForUpdateByIdAndTenantId(id, "tenant-a")).thenReturn(Optional.of(request));
        when(requests.saveAndFlush(any())).thenAnswer(invocation -> invocation.getArgument(0));

        assertThat(expiry.expireIfDue("tenant-a", id, Instant.parse("2026-07-25T12:00:00Z"))).isTrue();
        assertThat(request.getStatus()).isEqualTo(IdentityControlRequest.Status.EXPIRED);
        verify(audit).logRequired(any(), any(), org.mockito.ArgumentMatchers.eq("EXPIRE_IDENTITY_CONTROL_REQUEST"),
                any(), any(), any(), any(), any());

        when(requests.findForUpdateByIdAndTenantId(id, "tenant-a")).thenReturn(Optional.of(request));
        assertThat(expiry.expireIfDue("tenant-a", id, Instant.parse("2026-07-25T12:01:00Z"))).isTrue();
        verify(audit, org.mockito.Mockito.times(1)).logRequired(any(), any(),
                org.mockito.ArgumentMatchers.eq("EXPIRE_IDENTITY_CONTROL_REQUEST"), any(), any(), any(), any(), any());
    }
}
