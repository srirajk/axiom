package com.openwolf.iam.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.openwolf.iam.dto.SubjectContextResponse;
import com.openwolf.iam.entity.Principal;
import com.openwolf.iam.entity.Role;
import com.openwolf.iam.repository.PrincipalRepository;
import org.junit.jupiter.api.Test;

import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class SubjectContextServiceTest {
    private final PrincipalRepository repository = mock(PrincipalRepository.class);
    private final SubjectContextService service = new SubjectContextService(repository, new ObjectMapper());

    @Test
    void derivesCanonicalTenantBoundEntitlementsAndStableOpaqueRevision() {
        Principal principal = new Principal("subject-1", "tenant-a", "alice", "alice@example.test",
                "not-returned", true,
                "{\"admin_domains\":[\"risk\",\"finance\"],\"segments\":{\"claims\":\"internal\"},"
                        + "\"use_case_scope_mode\":\"listed_only\","
                        + "\"use_case_scopes\":[\"claims\",\"underwriting\"],\"classification\":\"internal\"}");
        Role reader = new Role("tenant-a", "reader", "[\"subject:read\",\"agent:read\"]", "reader");
        reader.setId(UUID.fromString("00000000-0000-0000-0000-000000000001"));
        Role admin = new Role("tenant-a", "platform_admin", "[\"subject:read\",\"platform:manage\"]", "admin");
        admin.setId(UUID.fromString("00000000-0000-0000-0000-000000000002"));
        principal.assignRole(reader);
        principal.assignRole(admin);
        when(repository.findByIdAndTenantId(eq("subject-1"), eq("tenant-a")))
                .thenReturn(Optional.of(principal));

        SubjectContextResponse result = service.resolve("subject-1", "tenant-a").orElseThrow();
        SubjectContextResponse rerun = service.resolve("subject-1", "tenant-a").orElseThrow();

        assertThat(result.subjectId()).isEqualTo("subject-1");
        assertThat(result.tenantId()).isEqualTo("tenant-a");
        assertThat(result.active()).isTrue();
        assertThat(result.roles()).containsExactly("platform_admin", "reader");
        assertThat(result.domains()).containsExactly("claims", "finance", "risk");
        assertThat(result.attributes()).containsOnlyKeys("classification")
                .containsEntry("classification", "internal");
        assertThat(result.entitlementRevision()).hasSize(64).isEqualTo(rerun.entitlementRevision());
        assertThat(result.entitlementRevision()).doesNotContain("not-returned", "alice@example.test");
    }

    @Test
    void missingOrInactiveSubjectsReturnNoContext() {
        when(repository.findByIdAndTenantId("missing", "tenant-a")).thenReturn(Optional.empty());
        assertThat(service.resolve("missing", "tenant-a")).isEmpty();

        Principal inactive = new Principal("inactive", "tenant-a", "inactive", null,
                "not-returned", false, "{}");
        when(repository.findByIdAndTenantId("inactive", "tenant-a")).thenReturn(Optional.of(inactive));
        assertThat(service.resolve("inactive", "tenant-a")).isEmpty();
    }

    @Test
    void defaultsToAllInAssignedDomainsOnlyWhenNoUseCaseListIsPresent() {
        Principal principal = new Principal("subject-2", "tenant-a", "bob", null,
                "not-returned", true, "{\"admin_domains\":[\"finance\"]}");
        when(repository.findByIdAndTenantId("subject-2", "tenant-a")).thenReturn(Optional.of(principal));

        SubjectContextResponse result = service.resolve("subject-2", "tenant-a").orElseThrow();

        assertThat(result.domains()).containsExactly("finance");
    }

    @Test
    void derivesDomainsFromLegacyListFormSegments() {
        Principal principal = new Principal("subject-list", "tenant-a", "builder", null,
                "not-returned", true,
                "{\"admin_domains\":[\"finance\"],\"segments\":[\"wealth\",\"finance\"]}");
        when(repository.findByIdAndTenantId("subject-list", "tenant-a")).thenReturn(Optional.of(principal));

        SubjectContextResponse result = service.resolve("subject-list", "tenant-a").orElseThrow();

        assertThat(result.domains()).containsExactly("finance", "wealth");
    }

    @Test
    void rejectsIncoherentUseCaseScopeState() {
        Principal principal = new Principal("subject-3", "tenant-a", "carol", null,
                "not-returned", true, "{\"use_case_scope_mode\":\"listed_only\"}");
        when(repository.findByIdAndTenantId("subject-3", "tenant-a")).thenReturn(Optional.of(principal));

        assertThatThrownBy(() -> service.resolve("subject-3", "tenant-a"))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("listed_only requires non-empty");
    }
}
