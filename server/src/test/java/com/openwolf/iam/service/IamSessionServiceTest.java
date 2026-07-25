package com.openwolf.iam.service;

import com.openwolf.iam.auth.ExecutionTenant;
import com.openwolf.iam.dto.RevokeIamSessionRequest;
import com.openwolf.iam.entity.IamSession;
import com.openwolf.iam.repository.IamSessionRepository;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.AfterEach;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class IamSessionServiceTest {
    private final IamSessionRepository sessions = mock(IamSessionRepository.class);
    private final ExecutionTenant executionTenant = mock(ExecutionTenant.class);
    private final AuditService audit = mock(AuditService.class);
    private final Instant now = Instant.parse("2026-07-25T12:00:00Z");
    private final IamSessionService service = new IamSessionService(sessions, executionTenant, audit,
            Clock.fixed(now, ZoneOffset.UTC));

    @AfterEach
    void clearSecurity() { SecurityContextHolder.clearContext(); }

    @Test
    void authorizationIdProducesStableDurableSessionAndRevokeUsesRevision() {
        UUID applicationId = UUID.randomUUID();
        AtomicReference<IamSession> stored = new AtomicReference<>();
        when(sessions.findById(any())).thenAnswer(invocation -> Optional.ofNullable(stored.get()));
        when(sessions.save(any())).thenAnswer(invocation -> {
            IamSession saved = invocation.getArgument(0);
            stored.set(saved);
            return saved;
        });

        UUID first = service.issue("authorization-1", "tenant-a", "principal-a", applicationId,
                "client-a", now.plusSeconds(3600));
        UUID second = service.issue("authorization-1", "tenant-a", "principal-a", applicationId,
                "client-a", now.plusSeconds(3600));

        assertThat(first).isEqualTo(second);
        verify(sessions).save(any(IamSession.class));

        IamSession session = new IamSession(first, "tenant-a", "principal-a", applicationId, "client-a",
                now, now.plusSeconds(3600));
        when(executionTenant.require()).thenReturn("tenant-a");
        when(sessions.findByIdAndTenantId(first, "tenant-a")).thenReturn(Optional.of(session));
        SecurityContextHolder.getContext().setAuthentication(
                new TestingAuthenticationToken("admin", "", "ROLE_tenant_admin"));

        assertThat(service.revoke("tenant-a", first, new RevokeIamSessionRequest(1L), null).status())
                .isEqualTo(IamSession.Status.REVOKED);
        assertThat(service.active(first, "tenant-a", now)).isFalse();
    }

    @Test
    void staleRevisionCannotRevoke() {
        UUID id = UUID.randomUUID();
        IamSession session = new IamSession(id, "tenant-a", "principal-a", null, "client-a", now,
                now.plusSeconds(3600));
        when(executionTenant.require()).thenReturn("tenant-a");
        when(sessions.findByIdAndTenantId(id, "tenant-a")).thenReturn(Optional.of(session));
        SecurityContextHolder.getContext().setAuthentication(
                new TestingAuthenticationToken("admin", "", "ROLE_tenant_admin"));

        assertThatThrownBy(() -> service.revoke("tenant-a", id, new RevokeIamSessionRequest(0L), null))
                .isInstanceOf(com.openwolf.iam.exception.ResourceConflictException.class)
                .hasMessageContaining("stale");
    }
}
