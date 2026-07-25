package com.openwolf.iam.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.openwolf.iam.repository.GroupRepository;
import com.openwolf.iam.repository.PrincipalRepository;
import com.openwolf.iam.repository.ScimResourceLinkRepository;
import com.openwolf.iam.scim.ScimException;
import com.openwolf.iam.entity.Group;
import com.openwolf.iam.entity.Principal;
import com.openwolf.iam.entity.ScimProvisioningSource;
import com.openwolf.iam.entity.ScimResourceLink;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.mockito.ArgumentMatchers.any;

class ScimServiceTest {
    @Test
    void advertisesOnlyImplementedCapabilitiesAndSchemas() {
        ScimService service = new ScimService(mock(PrincipalRepository.class), mock(GroupRepository.class),
                mock(ScimResourceLinkRepository.class), new ObjectMapper(), mock(org.springframework.security.crypto.password.PasswordEncoder.class), mock(AuditService.class));
        var config = service.discovery("config");
        assertThat(config.path("patch").path("supported").asBoolean()).isTrue();
        assertThat(config.path("bulk").path("supported").asBoolean()).isFalse();
        assertThat(service.discovery("schemas").path("Resources").size()).isEqualTo(2);
    }

    @Test
    void rejectsUnimplementedFilterShapeAndSort() {
        ScimService service = new ScimService(mock(PrincipalRepository.class), mock(GroupRepository.class),
                mock(ScimResourceLinkRepository.class), new ObjectMapper(), mock(org.springframework.security.crypto.password.PasswordEncoder.class), mock(AuditService.class));
        var source = new com.openwolf.iam.entity.ScimProvisioningSource("tenant-a", null, "Directory", "selector", "hash");
        assertThatThrownBy(() -> service.list(source, "User", 1, 10, "userName eq \"alice\"", null, null))
                .isInstanceOf(ScimException.class).hasMessageContaining("externalId");
        assertThatThrownBy(() -> service.list(source, "User", 1, 10, null, "userName", null))
                .isInstanceOf(ScimException.class).hasMessageContaining("sort");
    }

    @Test
    void groupPutReplacesMembershipsWhenMembersAreOmitted() {
        PrincipalRepository principals = mock(PrincipalRepository.class);
        GroupRepository groups = mock(GroupRepository.class);
        ScimResourceLinkRepository links = mock(ScimResourceLinkRepository.class);
        ObjectMapper mapper = new ObjectMapper();
        ScimService service = new ScimService(principals, groups, links, mapper,
                mock(org.springframework.security.crypto.password.PasswordEncoder.class), mock(AuditService.class));
        ScimProvisioningSource source = new ScimProvisioningSource("tenant-a", null, "Directory", "selector", "hash");
        Group group = new Group("tenant-a", "old", null, null, "{}");
        group.setId(java.util.UUID.randomUUID()); group.setScimSourceId(source.getId());
        group.getMembers().add(new Principal("user-1", "tenant-a", "one", null, "hash", true, "{}"));
        ScimResourceLink link = new ScimResourceLink(source.getId(), "tenant-a", "Group", "external-1", group.getId().toString(), "[\"displayName\",\"members\"]");
        when(links.findBySourceIdAndResourceTypeAndResourceId(source.getId(), "Group", group.getId().toString())).thenReturn(java.util.Optional.of(link));
        when(groups.findByIdAndTenantId(group.getId(), "tenant-a")).thenReturn(java.util.Optional.of(group));
        when(groups.save(any())).thenAnswer(invocation -> invocation.getArgument(0));
        var replacement = mapper.createObjectNode().put("displayName", "new");

        service.replace(source, "Group", group.getId().toString(), replacement, "1", null);

        assertThat(group.getMembers()).isEmpty();
        assertThat(group.getName()).isEqualTo("new");
    }
}
