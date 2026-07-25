package com.openwolf.iam.service;

import com.openwolf.iam.auth.ExecutionTenant;
import com.openwolf.iam.dto.EnrollRecoveryOperatorRequest;
import com.openwolf.iam.dto.RecoveryOperatorTransitionRequest;
import com.openwolf.iam.dto.RecoveryOperatorResponse;
import com.openwolf.iam.entity.Principal;
import com.openwolf.iam.entity.RecoveryOperator;
import com.openwolf.iam.entity.IamSession;
import com.openwolf.iam.repository.IamSessionRepository;
import com.openwolf.iam.repository.PrincipalRepository;
import com.openwolf.iam.repository.RecoveryOperatorRepository;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.Jwt;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Optional;
import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class RecoveryOperatorSodTest {
    private static final String TENANT = "tenant-a";
    private static final Instant NOW = Instant.parse("2026-07-25T12:00:00Z");
    private final RecoveryOperatorRepository operators = mock(RecoveryOperatorRepository.class);
    private final PrincipalRepository principals = mock(PrincipalRepository.class);
    private final ExecutionTenant executionTenant = mock(ExecutionTenant.class);
    private final PasswordEncoder passwords = mock(PasswordEncoder.class);
    private final AuditService audit = mock(AuditService.class);
    private final RecoveryAuditService recoveryAudit = mock(RecoveryAuditService.class);
    private final IamSessionRepository sessions = mock(IamSessionRepository.class);
    private final RecoveryOperatorService service = new RecoveryOperatorService(operators, principals, executionTenant,
            passwords, audit, sessions, recoveryAudit, Clock.fixed(NOW, ZoneOffset.UTC));

    @AfterEach
    void clear() { SecurityContextHolder.clearContext(); }

    @Test
    void adminCannotEnrollSelfOrReceiveEitherCredential() {
        authorize("admin", false);
        when(audit.currentActor()).thenReturn("admin");
        when(principals.findByIdAndTenantId("target", TENANT)).thenReturn(Optional.of(active("target")));

        assertThatThrownBy(() -> service.enroll(TENANT, new EnrollRecoveryOperatorRequest("admin"), null))
                .isInstanceOf(com.openwolf.iam.exception.ResourceConflictException.class);
        when(operators.findByTenantIdAndPrincipalId(TENANT, "target")).thenReturn(Optional.empty());
        when(operators.saveAndFlush(any())).thenAnswer(invocation -> invocation.getArgument(0));
        var response = service.enroll(TENANT, new EnrollRecoveryOperatorRequest("target"), null);

        assertThat(response.status()).isEqualTo(RecoveryOperator.Status.PENDING_ACTIVATION);
        assertThat(response.oneTimeCredential()).isNull();
        verify(operators).saveAndFlush(any(RecoveryOperator.class));
    }

    @Test
    void onlyExactNormalTargetCanActivateAndEachTargetGetsOnlyItsOwnCredential() {
        RecoveryOperator first = RecoveryOperator.pending(TENANT, "target-a", "admin", NOW);
        RecoveryOperator second = RecoveryOperator.pending(TENANT, "target-b", "admin", NOW);
        when(executionTenant.require()).thenReturn(TENANT);
        when(operators.findByIdAndTenantIdForUpdate(first.getId(), TENANT)).thenReturn(Optional.of(first));
        when(operators.findByIdAndTenantIdForUpdate(second.getId(), TENANT)).thenReturn(Optional.of(second));
        when(principals.findByIdAndTenantId("target-a", TENANT)).thenReturn(Optional.of(active("target-a")));
        when(principals.findByIdAndTenantId("target-b", TENANT)).thenReturn(Optional.of(active("target-b")));
        when(passwords.encode(any())).thenReturn("new-hash");
        when(sessions.findActiveRecoverySessionsForOperatorForUpdate(any(), any(), any())).thenReturn(List.of());

        authorize("other", false);
        assertThatThrownBy(() -> service.activateSelf(first.getId(), new RecoveryOperatorTransitionRequest(1L), null))
                .isInstanceOf(com.openwolf.iam.exception.ResourceConflictException.class);
        authorize("target-a", false);
        var firstResponse = service.activateSelf(first.getId(), new RecoveryOperatorTransitionRequest(1L), null);
        authorize("target-b", false);
        var secondResponse = service.activateSelf(second.getId(), new RecoveryOperatorTransitionRequest(1L), null);

        assertThat(firstResponse.oneTimeCredential()).isNotBlank();
        assertThat(secondResponse.oneTimeCredential()).isNotBlank();
        assertThat(first.getActivationActorId()).isEqualTo("target-a");
        assertThat(second.getActivationActorId()).isEqualTo("target-b");
    }

    @Test
    void impersonatedTargetCannotActivatePendingOperator() {
        RecoveryOperator pending = RecoveryOperator.pending(TENANT, "target", "admin", NOW);
        when(executionTenant.require()).thenReturn(TENANT);
        authorize("target", true);

        assertThatThrownBy(() -> service.activateSelf(pending.getId(), new RecoveryOperatorTransitionRequest(1L), null))
                .isInstanceOf(com.openwolf.iam.exception.ResourceConflictException.class);
        verify(operators, never()).findByIdAndTenantIdForUpdate(any(), any());
    }

    @Test
    void selfInventoryIsTenantAndPrincipalBoundAndRedacted() {
        RecoveryOperator operator = RecoveryOperator.pending(TENANT, "target", "admin", NOW);
        when(executionTenant.require()).thenReturn(TENANT);
        authorize("target", false);
        when(operators.findByTenantIdAndPrincipalId(TENANT, "target")).thenReturn(Optional.of(operator));

        var result = service.selfList();

        assertThat(result).singleElement().satisfies(view -> {
            assertThat(view.id()).isEqualTo(operator.getId());
            assertThat(view.principalId()).isEqualTo("target");
            assertThat(view.tenantId()).isEqualTo(TENANT);
            assertThat(view.revision()).isEqualTo(1L);
            assertThat(view.oneTimeCredential()).isNull();
        });
        verify(operators).findByTenantIdAndPrincipalId(TENANT, "target");
    }

    @Test
    void adminRotationReturnsNoCredentialAndRevokesSessionsImmediately() {
        RecoveryOperator active = new RecoveryOperator(TENANT, "target", "old-hash", NOW);
        IamSession affected = recoverySession(active.getId());
        when(executionTenant.require()).thenReturn(TENANT);
        when(audit.currentActor()).thenReturn("admin");
        when(operators.findByIdAndTenantIdForUpdate(active.getId(), TENANT)).thenReturn(Optional.of(active));
        when(sessions.findActiveRecoverySessionsForOperatorForUpdate(TENANT, active.getId(),
                com.openwolf.iam.entity.IamSession.Status.ACTIVE)).thenReturn(List.of(affected));
        when(operators.saveAndFlush(any())).thenAnswer(invocation -> {
            RecoveryOperator saved = invocation.getArgument(0);
            setRevision(saved, saved.getRevision() + 1);
            return saved;
        });
        when(sessions.saveAndFlush(any())).thenAnswer(invocation -> invocation.getArgument(0));

        var response = service.rotate(TENANT, active.getId(), new RecoveryOperatorTransitionRequest(1L), null);

        assertThat(response.status()).isEqualTo(RecoveryOperator.Status.PENDING_ROTATION);
        assertThat(response.oneTimeCredential()).isNull();
        assertThat(affected.getStatus()).isEqualTo(com.openwolf.iam.entity.IamSession.Status.REVOKED);
        verify(audit).logRequired(any(), any(), org.mockito.ArgumentMatchers.eq("REVOKE_IDENTITY_RECOVERY_SESSION"),
                org.mockito.ArgumentMatchers.eq("session"), org.mockito.ArgumentMatchers.eq(affected.getId().toString()),
                any(), any(), any());
    }

    @Test
    void adminDisableAuditsEachAffectedRecoverySession() {
        RecoveryOperator active = new RecoveryOperator(TENANT, "target", "old-hash", NOW);
        IamSession affected = recoverySession(active.getId());
        when(executionTenant.require()).thenReturn(TENANT);
        when(audit.currentActor()).thenReturn("admin");
        when(operators.findByIdAndTenantIdForUpdate(active.getId(), TENANT)).thenReturn(Optional.of(active));
        when(sessions.findActiveRecoverySessionsForOperatorForUpdate(TENANT, active.getId(),
                com.openwolf.iam.entity.IamSession.Status.ACTIVE)).thenReturn(List.of(affected));
        when(operators.saveAndFlush(any())).thenAnswer(invocation -> invocation.getArgument(0));
        when(sessions.saveAndFlush(any())).thenAnswer(invocation -> invocation.getArgument(0));

        service.disable(TENANT, active.getId(), new RecoveryOperatorTransitionRequest(1L), null);

        assertThat(affected.getStatus()).isEqualTo(com.openwolf.iam.entity.IamSession.Status.REVOKED);
        verify(audit).logRequired(any(), any(), org.mockito.ArgumentMatchers.eq("REVOKE_IDENTITY_RECOVERY_SESSION"),
                org.mockito.ArgumentMatchers.eq("session"), org.mockito.ArgumentMatchers.eq(affected.getId().toString()),
                any(), any(), any());
    }

    @Test
    void returnedPostFlushRevisionChainsIntoRotationWithoutRefetch() {
        RecoveryOperator operator = RecoveryOperator.pending(TENANT, "target", "admin", NOW);
        when(executionTenant.require()).thenReturn(TENANT);
        when(operators.findByIdAndTenantIdForUpdate(operator.getId(), TENANT)).thenReturn(Optional.of(operator));
        when(principals.findByIdAndTenantId("target", TENANT)).thenReturn(Optional.of(active("target")));
        when(passwords.encode(any())).thenReturn("new-hash");
        when(operators.saveAndFlush(any())).thenAnswer(invocation -> {
            RecoveryOperator saved = invocation.getArgument(0);
            setRevision(saved, saved.getRevision() + 1);
            return saved;
        });

        authorize("target", false);
        RecoveryOperatorResponse activated = service.activateSelf(operator.getId(),
                new RecoveryOperatorTransitionRequest(1L), null);
        when(audit.currentActor()).thenReturn("admin");
        RecoveryOperatorResponse pendingRotation = service.rotate(TENANT, operator.getId(),
                new RecoveryOperatorTransitionRequest(activated.revision()), null);
        authorize("target", false);
        RecoveryOperatorResponse reactivated = service.completeRotationSelf(operator.getId(),
                new RecoveryOperatorTransitionRequest(pendingRotation.revision()), null);

        assertThat(activated.revision()).isEqualTo(2L);
        assertThat(pendingRotation.revision()).isEqualTo(3L);
        assertThat(reactivated.revision()).isEqualTo(4L);
    }

    private void authorize(String subject, boolean impersonated) {
        when(executionTenant.require()).thenReturn(TENANT);
        SecurityContextHolder.getContext().setAuthentication(new UsernamePasswordAuthenticationToken(
                Jwt.withTokenValue("token").header("alg", "RS256").subject(subject)
                        .claim("tenant_id", TENANT).claim("impersonation", impersonated).build(), null));
    }

    private static Principal active(String id) { return new Principal(id, TENANT, id, null, "hash", true, "{}"); }

    private static com.openwolf.iam.entity.IamSession recoverySession(UUID operatorId) {
        return new com.openwolf.iam.entity.IamSession(UUID.randomUUID(), TENANT, "recovery:session", "recovery",
                NOW, NOW.plusSeconds(600), "identity-admin", operatorId, UUID.randomUUID());
    }

    private static void setRevision(RecoveryOperator operator, long revision) {
        try {
            var field = RecoveryOperator.class.getDeclaredField("revision");
            field.setAccessible(true);
            field.setLong(operator, revision);
        } catch (ReflectiveOperationException ex) {
            throw new AssertionError(ex);
        }
    }

}
