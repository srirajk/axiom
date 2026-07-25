package com.openwolf.iam.service;

import com.openwolf.iam.dto.RecoverySessionRequest;
import com.openwolf.iam.entity.Principal;
import com.openwolf.iam.entity.RecoveryOperator;
import com.openwolf.iam.repository.PrincipalRepository;
import com.openwolf.iam.repository.RecoveryOperatorRepository;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.security.crypto.password.PasswordEncoder;

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

class RecoverySessionServiceTest {
    @Test
    void issuesRecoveryMarkedTokenOnlyAfterTwoDistinctValidOperators() {
        RecoveryOperatorRepository operators = mock(RecoveryOperatorRepository.class);
        PrincipalRepository principals = mock(PrincipalRepository.class);
        PasswordEncoder passwords = mock(PasswordEncoder.class);
        IamSessionService sessions = mock(IamSessionService.class);
        JwtEncoder encoder = mock(JwtEncoder.class);
        RecoveryAuditService recoveryAudit = mock(RecoveryAuditService.class);
        AuditService audit = mock(AuditService.class);
        RecoveryOperator first = operator("tenant-a", "principal-a");
        RecoveryOperator second = operator("tenant-a", "principal-b");
        when(operators.findByTenantIdAndPrincipalIdForUpdate("tenant-a", "principal-a")).thenReturn(Optional.of(first));
        when(operators.findByTenantIdAndPrincipalIdForUpdate("tenant-a", "principal-b")).thenReturn(Optional.of(second));
        when(principals.findByIdAndTenantId("principal-a", "tenant-a")).thenReturn(Optional.of(active("principal-a")));
        when(principals.findByIdAndTenantId("principal-b", "tenant-a")).thenReturn(Optional.of(active("principal-b")));
        when(passwords.matches("credential-a", first.getCredentialHash())).thenReturn(true);
        when(passwords.matches("credential-b", second.getCredentialHash())).thenReturn(true);
        UUID sessionId = UUID.randomUUID();
        when(sessions.issueRecovery(any(), any(), any(), any(), any())).thenReturn(sessionId);
        when(encoder.encode(any(JwtEncoderParameters.class))).thenReturn(Jwt.withTokenValue("token")
                .header("alg", "RS256").claim("issued", true).build());
        RecoverySessionService service = new RecoverySessionService(operators, principals, passwords, sessions, encoder,
                recoveryAudit, audit, "http://localhost:8084", 600,
                Clock.fixed(Instant.parse("2026-07-25T12:00:00Z"), ZoneOffset.UTC));

        var response = service.issue(new RecoverySessionRequest("tenant-a", "principal-a", "credential-a",
                "principal-b", "credential-b"), null);

        assertThat(response.accessToken()).isEqualTo("token");
        assertThat(response.scope()).isEqualTo("identity-admin");
        verify(audit).logRequired(any(), any(), org.mockito.ArgumentMatchers.eq("ISSUE_IDENTITY_RECOVERY_SESSION"),
                any(), any(), any(), org.mockito.ArgumentMatchers.argThat(value -> value.toString().contains("identity-admin")), any());
    }

    @Test
    void rejectsSameOperatorWithoutCredentialLookup() {
        RecoveryOperatorRepository operators = mock(RecoveryOperatorRepository.class);
        RecoveryAuditService recoveryAudit = mock(RecoveryAuditService.class);
        RecoverySessionService service = new RecoverySessionService(operators, mock(PrincipalRepository.class),
                mock(PasswordEncoder.class), mock(IamSessionService.class), mock(JwtEncoder.class), recoveryAudit,
                mock(AuditService.class), "http://localhost:8084", 600, Clock.systemUTC());

        assertThatThrownBy(() -> service.issue(new RecoverySessionRequest("tenant-a", "same", "a", "same", "b"), null))
                .isInstanceOf(com.openwolf.iam.exception.ResourceConflictException.class)
                .hasMessageContaining("authentication failed");
        verify(recoveryAudit).rejected("tenant-a", "operators must be distinct");
    }

    private static RecoveryOperator operator(String tenant, String principal) {
        return new RecoveryOperator(tenant, principal, "hash-" + principal, Instant.now());
    }

    private static Principal active(String id) {
        return new Principal(id, "tenant-a", id, null, "hash", true, "{}");
    }
}
