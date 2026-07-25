package com.openwolf.iam.service;

import com.openwolf.iam.auth.ExecutionTenant;
import com.openwolf.iam.dto.ApplicationRoleResponse;
import com.openwolf.iam.dto.CreateApplicationRoleRequest;
import com.openwolf.iam.entity.Principal;
import com.openwolf.iam.entity.TenantApplication;
import com.openwolf.iam.entity.TenantApplicationClient;
import com.openwolf.iam.entity.TenantApplicationMembership;
import com.openwolf.iam.entity.TenantApplicationRole;
import com.openwolf.iam.entity.TenantApplicationRoleAssignment;
import com.openwolf.iam.exception.ResourceConflictException;
import com.openwolf.iam.repository.PrincipalRepository;
import com.openwolf.iam.repository.TenantApplicationClientRepository;
import com.openwolf.iam.repository.TenantApplicationMembershipRepository;
import com.openwolf.iam.repository.TenantApplicationRepository;
import com.openwolf.iam.repository.TenantApplicationRoleAssignmentRepository;
import com.openwolf.iam.repository.TenantApplicationRoleRepository;
import jakarta.servlet.http.HttpServletRequest;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import java.lang.reflect.Field;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.same;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class ApplicationAccessServiceTest {
    private final TenantApplicationRepository applications = mock(TenantApplicationRepository.class);
    private final TenantApplicationClientRepository clients = mock(TenantApplicationClientRepository.class);
    private final TenantApplicationMembershipRepository memberships = mock(TenantApplicationMembershipRepository.class);
    private final TenantApplicationRoleRepository roles = mock(TenantApplicationRoleRepository.class);
    private final TenantApplicationRoleAssignmentRepository assignments = mock(TenantApplicationRoleAssignmentRepository.class);
    private final PrincipalRepository principals = mock(PrincipalRepository.class);
    private final ExecutionTenant executionTenant = mock(ExecutionTenant.class);
    private final AuditService audit = mock(AuditService.class);
    private final ApplicationAccessService service = new ApplicationAccessService(applications, clients, memberships,
            roles, assignments, principals, executionTenant, audit);

    @Test
    void updateRolePersistsCanonicalPermissionsAndEffectsAndAuditsTheResult() {
        TenantApplication application = new TenantApplication("tenant-a", "portal", "Portal", "", "portal-api");
        TenantApplicationRole role = new TenantApplicationRole(application.getId(), "reviewer", "Reviewer", "",
                List.of("record.read"), Map.of("record.read", "read"));
        HttpServletRequest request = mock(HttpServletRequest.class);
        when(executionTenant.require()).thenReturn("tenant-a");
        when(applications.findByIdAndTenantId(application.getId(), "tenant-a"))
                .thenReturn(Optional.of(application));
        when(roles.findByIdAndApplicationId(role.getId(), application.getId())).thenReturn(Optional.of(role));
        when(roles.save(role)).thenReturn(role);
        when(audit.currentActor()).thenReturn("admin");
        when(request.getHeader("X-Correlation-ID")).thenReturn("corr-1");

        ApplicationRoleResponse response = service.updateRole("tenant-a", application.getId(), role.getId(),
                new CreateApplicationRoleRequest("reviewer", "Senior reviewer", "Can review and approve",
                        List.of("record.write", "record.read", "record.write"),
                        Map.of("record.write", "cosign", "record.read", "read")), request);

        assertThat(role.getRoleKey()).isEqualTo("reviewer");
        assertThat(role.getPermissions()).containsExactly("record.read", "record.write");
        assertThat(role.getPermissionEffects()).containsExactlyInAnyOrderEntriesOf(
                Map.of("record.read", "read", "record.write", "cosign"));
        assertThat(response.permissions()).containsExactly("record.read", "record.write");
        verify(roles).save(same(role));
        ArgumentCaptor<Object> after = ArgumentCaptor.forClass(Object.class);
        verify(audit).logRequired(eq("tenant-a"), eq("admin"), eq("UPDATE_APPLICATION_ROLE"),
                eq("application_role"), eq(role.getId().toString()), eq(null), after.capture(), eq("corr-1"));
        assertThat(after.getValue()).isEqualTo(response);
    }

    @Test
    void updateRoleRejectsAChangedRoleKeyWithoutPersistenceOrAudit() {
        TenantApplication application = new TenantApplication("tenant-a", "portal", "Portal", "", "portal-api");
        TenantApplicationRole role = new TenantApplicationRole(application.getId(), "reviewer", "Reviewer", "",
                List.of("record.read"));
        when(executionTenant.require()).thenReturn("tenant-a");
        when(applications.findByIdAndTenantId(application.getId(), "tenant-a"))
                .thenReturn(Optional.of(application));
        when(roles.findByIdAndApplicationId(role.getId(), application.getId())).thenReturn(Optional.of(role));

        assertThatThrownBy(() -> service.updateRole("tenant-a", application.getId(), role.getId(),
                new CreateApplicationRoleRequest("renamed", "Renamed", "", List.of("record.read"), null), null))
                .isInstanceOf(ResourceConflictException.class)
                .hasMessageContaining("immutable");

        assertThat(role.getRoleKey()).isEqualTo("reviewer");
        verify(roles, never()).save(any());
        verify(audit, never()).logRequired(any(), any(), any(), any(), any(), any(), any(), any());
    }

    @Test
    void tokenClaimsContainOnlyTheExactApplicationMembershipEntitlements() {
        Fixture fixture = activeFixture();
        TenantApplicationRole role = new TenantApplicationRole(fixture.application().getId(), "reader", "Reader", "",
                List.of("record.read", "record.read"));
        TenantApplicationRoleAssignment assignment = new TenantApplicationRoleAssignment(
                fixture.membership().getId(), role.getId(), "admin-grant", "admin");
        when(assignments.findByMembershipIdAndRevokedAtIsNull(fixture.membership().getId())).thenReturn(List.of(assignment));
        when(roles.findById(role.getId())).thenReturn(Optional.of(role));

        Map<String, Object> claims = service.tokenClaims("portal", "principal-a");

        assertThat(claims).containsEntry("tenant_id", "tenant-a")
                .containsEntry("application_id", "portal")
                .containsEntry("roles", List.of("reader"))
                .containsEntry("permissions", List.of("record.read"))
                .containsEntry("attributes", Map.of("region", "north"))
                .containsEntry("entitlement_revision", 2L);
        assertThat(claims).doesNotContainKey("platform_roles");
    }

    @Test
    void disabledMembershipCannotMintAnApplicationToken() {
        Fixture fixture = activeFixture();
        fixture.membership().disable();
        when(memberships.findByApplicationIdAndPrincipalId(fixture.application().getId(), "principal-a"))
                .thenReturn(Optional.of(fixture.membership()));

        assertThatThrownBy(() -> service.tokenClaims("portal", "principal-a"))
                .isInstanceOf(IllegalStateException.class).hasMessageContaining("not a member");
    }

    @Test
    void crossApplicationRoleAssignmentFailsClosedInsteadOfLeakingItsRole() {
        Fixture fixture = activeFixture();
        TenantApplication otherApplication = new TenantApplication("tenant-a", "other", "Other", "", "other-api");
        TenantApplicationRole role = new TenantApplicationRole(otherApplication.getId(), "operator", "Operator", "",
                List.of("record.write"));
        TenantApplicationRoleAssignment assignment = new TenantApplicationRoleAssignment(
                fixture.membership().getId(), role.getId(), "corrupt", "admin");
        when(assignments.findByMembershipIdAndRevokedAtIsNull(fixture.membership().getId())).thenReturn(List.of(assignment));
        when(roles.findById(role.getId())).thenReturn(Optional.of(role));

        assertThatThrownBy(() -> service.tokenClaims("portal", "principal-a"))
                .isInstanceOf(IllegalStateException.class).hasMessageContaining("crosses application scope");
    }

    @Test
    void mapsApplicationAttributesAndPermissionsAsJsonContainers() throws NoSuchFieldException {
        Field attributes = TenantApplicationMembership.class.getDeclaredField("attributes");
        Field permissions = TenantApplicationRole.class.getDeclaredField("permissions");

        assertThat(attributes.getType()).isEqualTo(Map.class);
        assertThat(attributes.getAnnotation(JdbcTypeCode.class).value()).isEqualTo(SqlTypes.JSON);
        assertThat(permissions.getType()).isEqualTo(List.class);
        assertThat(permissions.getAnnotation(JdbcTypeCode.class).value()).isEqualTo(SqlTypes.JSON);
    }

    @Test
    void disabledMembershipRequiresAnExplicitAuditedEnableBeforeItCanMintAgain() {
        Fixture fixture = activeFixture();
        fixture.membership().disable();
        when(executionTenant.require()).thenReturn("tenant-a");
        when(applications.findByIdAndTenantId(fixture.application().getId(), "tenant-a"))
                .thenReturn(Optional.of(fixture.application()));
        when(memberships.findByIdAndApplicationId(fixture.membership().getId(), fixture.application().getId()))
                .thenReturn(Optional.of(fixture.membership()));
        when(memberships.save(fixture.membership())).thenReturn(fixture.membership());

        service.enableMembership("tenant-a", fixture.application().getId(), fixture.membership().getId(), null);

        assertThat(fixture.membership().getStatus()).isEqualTo(TenantApplicationMembership.Status.ACTIVE);
        assertThat(fixture.membership().getEntitlementRevision()).isEqualTo(4L);
    }

    private Fixture activeFixture() {
        TenantApplication application = new TenantApplication("tenant-a", "portal", "Portal", "", "portal-api");
        TenantApplicationClient client = new TenantApplicationClient(application.getId(), "portal",
                TenantApplicationClient.Type.PUBLIC_BROWSER, List.of("openid"));
        Principal principal = new Principal("principal-a", "tenant-a", "principal-a", "principal@example.test",
                "not-a-login-secret", true, "{}");
        TenantApplicationMembership membership = new TenantApplicationMembership(application.getId(), principal.getId(),
                "admin-grant", "admin");
        membership.replaceAttributes(Map.of("region", "north"));
        when(clients.findByClientId("portal")).thenReturn(Optional.of(client));
        when(applications.findById(application.getId())).thenReturn(Optional.of(application));
        when(principals.findByIdAndTenantId("principal-a", "tenant-a")).thenReturn(Optional.of(principal));
        when(memberships.findByApplicationIdAndPrincipalId(application.getId(), "principal-a")).thenReturn(Optional.of(membership));
        return new Fixture(application, membership);
    }

    private record Fixture(TenantApplication application, TenantApplicationMembership membership) {}
}
