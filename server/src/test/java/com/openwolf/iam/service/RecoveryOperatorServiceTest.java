package com.openwolf.iam.service;

import com.openwolf.iam.auth.ExecutionTenant;
import com.openwolf.iam.dto.EnrollRecoveryOperatorRequest;
import com.openwolf.iam.entity.Principal;
import com.openwolf.iam.repository.PrincipalRepository;
import com.openwolf.iam.repository.RecoveryOperatorRepository;
import com.openwolf.iam.repository.IamSessionRepository;
import org.junit.jupiter.api.Test;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class RecoveryOperatorServiceTest {
    @Test
    void enrollmentReturnsCredentialOnceAndAuditsWithoutIt() {
        RecoveryOperatorRepository operators = mock(RecoveryOperatorRepository.class);
        PrincipalRepository principals = mock(PrincipalRepository.class);
        ExecutionTenant tenant = mock(ExecutionTenant.class);
        PasswordEncoder passwords = mock(PasswordEncoder.class);
        AuditService audit = mock(AuditService.class);
        when(tenant.require()).thenReturn("tenant-a");
        when(principals.findByIdAndTenantId("principal-a", "tenant-a"))
                .thenReturn(Optional.of(new Principal("principal-a", "tenant-a", "alice", null, "hash", true, "{}")));
        when(operators.findByTenantIdAndPrincipalId("tenant-a", "principal-a")).thenReturn(Optional.empty());
        when(passwords.encode(any())).thenReturn("bcrypt-hash");
        when(operators.saveAndFlush(any())).thenAnswer(invocation -> invocation.getArgument(0));
        RecoveryOperatorService service = new RecoveryOperatorService(operators, principals, tenant, passwords, audit,
                mock(IamSessionRepository.class), null,
                Clock.fixed(Instant.parse("2026-07-25T12:00:00Z"), ZoneOffset.UTC));

        var response = service.enroll("tenant-a", new EnrollRecoveryOperatorRequest("principal-a"), null);

        assertThat(response.status()).isEqualTo(com.openwolf.iam.entity.RecoveryOperator.Status.PENDING_ACTIVATION);
        assertThat(response.oneTimeCredential()).isNull();
        verify(audit).logRequired(any(), any(), any(), any(), any(), any(),
                org.mockito.ArgumentMatchers.argThat(value -> value instanceof com.openwolf.iam.dto.RecoveryOperatorResponse r
                        && r.oneTimeCredential() == null), any());
    }
}
