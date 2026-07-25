package com.openwolf.iam.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.openwolf.iam.auth.ExecutionTenant;
import com.openwolf.iam.dto.GroupResponse;
import com.openwolf.iam.dto.UserResponse;
import com.openwolf.iam.entity.Group;
import com.openwolf.iam.entity.Principal;
import com.openwolf.iam.repository.GroupRepository;
import com.openwolf.iam.repository.PrincipalRepository;
import org.junit.jupiter.api.Test;
import org.springframework.data.jpa.repository.Query;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class GroupServiceDomainAssignmentsTest {
    private final GroupRepository groups = mock(GroupRepository.class);
    private final PrincipalRepository principals = mock(PrincipalRepository.class);
    private final UserService users = mock(UserService.class);
    private final ExecutionTenant tenant = mock(ExecutionTenant.class);
    private final GroupService service = new GroupService(groups, principals, mock(AuditService.class), users,
            new ObjectMapper(), tenant);

    @Test
    void domainBackedGroupUsesTheCanonicalDomainUnionInsteadOfLegacyMembers() {
        UUID groupId = UUID.randomUUID();
        Group group = new Group("tenant-a", "Banking", "banking", "", "{}");
        group.setId(groupId);
        Principal adminDomain = new Principal("subject-1", "tenant-a", "steward", "steward@example.test",
                "not-returned", true, "{\"admin_domains\":[\"banking\"]}");
        Principal listSegment = new Principal("subject-2", "tenant-a", "builder-list", "list@example.test",
                "not-returned", true, "{\"segments\":[\"banking\"]}");
        Principal mapSegment = new Principal("subject-3", "tenant-a", "builder-map", "map@example.test",
                "not-returned", true, "{\"segments\":{\"banking\":\"internal\"}}");
        UserResponse adminResponse = new UserResponse("subject-1", "steward", "steward@example.test", true,
                List.of(), java.util.Map.of(), "internal", List.of("banking"), null);
        UserResponse listResponse = new UserResponse("subject-2", "builder-list", "list@example.test", true,
                List.of(), java.util.Map.of("banking", "internal"), "internal", List.of(), null);
        UserResponse mapResponse = new UserResponse("subject-3", "builder-map", "map@example.test", true,
                List.of(), java.util.Map.of("banking", "internal"), "internal", List.of(), null);
        when(principals.findByTenantIdAndCanonicalDomain("tenant-a", "banking"))
                .thenReturn(List.of(adminDomain, listSegment, mapSegment));
        when(users.toUserResponse(adminDomain)).thenReturn(adminResponse);
        when(users.toUserResponse(listSegment)).thenReturn(listResponse);
        when(users.toUserResponse(mapSegment)).thenReturn(mapResponse);
        when(tenant.require()).thenReturn("tenant-a");
        when(groups.findByIdAndTenantId(groupId, "tenant-a")).thenReturn(Optional.of(group));

        GroupResponse summary = service.toGroupResponse(group);
        List<UserResponse> members = service.listMembers(groupId);

        assertThat(summary.memberCount()).isEqualTo(3);
        assertThat(members).containsExactly(adminResponse, listResponse, mapResponse);
        verify(groups, never()).countMembersById(any());
        verify(principals, times(2)).findByTenantIdAndCanonicalDomain(eq("tenant-a"), eq("banking"));
    }

    @Test
    void ordinaryTeamRetainsLegacyGroupMembershipCount() {
        Group group = new Group("tenant-a", "Operations", null, "", "{}");
        group.setId(UUID.randomUUID());
        when(groups.countMembersById(group.getId())).thenReturn(2);

        GroupResponse summary = service.toGroupResponse(group);

        assertThat(summary.memberCount()).isEqualTo(2);
        verify(principals, never()).findByTenantIdAndCanonicalDomain(any(), any());
    }

    @Test
    void canonicalDomainRepositoryContractExcludesInactivePrincipals() throws NoSuchMethodException {
        Query query = PrincipalRepository.class
                .getMethod("findByTenantIdAndCanonicalDomain", String.class, String.class)
                .getAnnotation(Query.class);

        assertThat(query.value()).contains("is_active = true");
    }

    @Test
    void domainBackedGroupRejectsLegacyMembershipWrites() {
        UUID groupId = UUID.randomUUID();
        Group group = new Group("tenant-a", "Banking", "banking", "", "{}");
        group.setId(groupId);
        when(tenant.require()).thenReturn("tenant-a");
        when(groups.findByIdAndTenantId(groupId, "tenant-a")).thenReturn(Optional.of(group));

        assertThatThrownBy(() -> service.addMember(groupId, "subject-1", mock(jakarta.servlet.http.HttpServletRequest.class)))
                .isInstanceOf(com.openwolf.iam.exception.ResourceConflictException.class)
                .hasMessageContaining("Domain assignments");
        verify(principals, never()).findByIdAndTenantId(any(), any());
    }
}
