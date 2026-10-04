package com.openwolf.iam.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.openwolf.iam.auth.ExecutionTenant;
import com.openwolf.iam.dto.CreateUserRequest;
import com.openwolf.iam.dto.UpdateUserRequest;
import com.openwolf.iam.entity.Principal;
import com.openwolf.iam.exception.ResourceConflictException;
import com.openwolf.iam.repository.GroupRepository;
import com.openwolf.iam.repository.PrincipalRepository;
import com.openwolf.iam.repository.RoleRepository;
import jakarta.persistence.EntityManager;
import jakarta.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.Test;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.Map;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class UserServiceCreateUserSafetyTest {
    private final PrincipalRepository principals = mock(PrincipalRepository.class);
    private final EntityManager entityManager = mock(EntityManager.class);
    private final IamSessionService sessions = mock(IamSessionService.class);
    private final PasswordEncoder passwords = mock(PasswordEncoder.class);
    private final ExecutionTenant tenant = mock(ExecutionTenant.class);
    private final UserService service = new UserService(principals, entityManager, sessions,
            mock(RoleRepository.class), mock(GroupRepository.class), mock(AuditService.class),
            passwords, new ObjectMapper(), tenant);

    @Test
    void duplicateGlobalIdCannotOverwriteAnotherTenantPrincipal() {
        when(tenant.require()).thenReturn("tenant-a");
        when(principals.existsById("bootstrap-admin")).thenReturn(true);

        assertThatThrownBy(() -> service.createUser(request("bootstrap-admin", "new-user"),
                mock(HttpServletRequest.class)))
                .isInstanceOf(ResourceConflictException.class)
                .hasMessageContaining("User ID already taken");
        verify(entityManager, never()).persist(any());
        verify(principals, never()).save(any(Principal.class));
    }

    @Test
    void uniqueIdUsesInsertOnlyPersistNotJpaMerge() {
        when(tenant.require()).thenReturn("tenant-a");
        when(principals.findByUsername("new-user")).thenReturn(Optional.empty());
        when(passwords.encode("secret")).thenReturn("encoded");

        var created = service.createUser(request("new-id", "new-user"),
                mock(HttpServletRequest.class));

        assertThat(created.id()).isEqualTo("new-id");
        verify(entityManager).persist(any(Principal.class));
        verify(principals, never()).save(any(Principal.class));
    }

    @Test
    void disablingUserRevokesEveryRootSessionInSameServiceCall() {
        when(tenant.require()).thenReturn("tenant-a");
        when(principals.findByIdAndTenantIdForUpdate("user-1", "tenant-a"))
                .thenReturn(Optional.of(principal()));

        var updated = service.updateUser("user-1", new UpdateUserRequest(null, false, null),
                mock(HttpServletRequest.class));

        assertThat(updated.isActive()).isFalse();
        verify(sessions).revokeAllForPrincipal("tenant-a", "user-1");
    }

    @Test
    void softDeletingUserRevokesEveryRootSession() {
        when(tenant.require()).thenReturn("tenant-a");
        when(principals.findByIdAndTenantIdForUpdate("user-1", "tenant-a"))
                .thenReturn(Optional.of(principal()));

        service.deleteUser("user-1", mock(HttpServletRequest.class));

        verify(sessions).revokeAllForPrincipal("tenant-a", "user-1");
    }

    @Test
    void emailOnlyUpdateDoesNotRevokeSessions() {
        when(tenant.require()).thenReturn("tenant-a");
        when(principals.findByIdAndTenantIdForUpdate("user-1", "tenant-a"))
                .thenReturn(Optional.of(principal()));

        service.updateUser("user-1", new UpdateUserRequest("changed@example.test", null, null),
                mock(HttpServletRequest.class));

        verify(sessions, never()).revokeAllForPrincipal("tenant-a", "user-1");
    }

    @Test
    void noOpActiveTrueOnActiveUserDoesNotRevokeSessions() {
        when(tenant.require()).thenReturn("tenant-a");
        when(principals.findByIdAndTenantIdForUpdate("user-1", "tenant-a"))
                .thenReturn(Optional.of(principal()));

        service.updateUser("user-1", new UpdateUserRequest(null, true, null), mock(HttpServletRequest.class));

        verify(sessions, never()).revokeAllForPrincipal("tenant-a", "user-1");
    }

    @Test
    void reEnablingDisabledUserSweepsSessions() {
        when(tenant.require()).thenReturn("tenant-a");
        Principal disabled = principal();
        disabled.setActive(false);
        when(principals.findByIdAndTenantIdForUpdate("user-1", "tenant-a")).thenReturn(Optional.of(disabled));

        var updated = service.updateUser("user-1", new UpdateUserRequest(null, true, null),
                mock(HttpServletRequest.class));

        assertThat(updated.isActive()).isTrue();
        verify(sessions).revokeAllForPrincipal("tenant-a", "user-1");
    }

    private static Principal principal() {
        return new Principal("user-1", "tenant-a", "person", "person@example.test", "encoded", true, "{}");
    }

    private static CreateUserRequest request(String id, String username) {
        return new CreateUserRequest(id, username, "new@example.test", "secret", Map.of());
    }
}
