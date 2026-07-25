package com.openwolf.iam.service;

import com.openwolf.iam.auth.ExecutionTenant;
import com.openwolf.iam.entity.Principal;
import com.openwolf.iam.entity.ScimProvisioningSource;
import com.openwolf.iam.entity.ScimResourceLink;
import com.openwolf.iam.repository.GroupRepository;
import com.openwolf.iam.repository.PrincipalRepository;
import com.openwolf.iam.repository.ScimProvisioningSourceRepository;
import com.openwolf.iam.repository.ScimResourceLinkRepository;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class ScimReconciliationServiceTest {
    @Test
    void reportsMissingAndOwnershipMismatchWithoutMutatingIdentityState() {
        ScimProvisioningSourceRepository sources = mock(ScimProvisioningSourceRepository.class);
        ScimResourceLinkRepository links = mock(ScimResourceLinkRepository.class);
        PrincipalRepository principals = mock(PrincipalRepository.class);
        AuditService audit = mock(AuditService.class);
        ExecutionTenant executionTenant = mock(ExecutionTenant.class);
        ScimProvisioningSource source = new ScimProvisioningSource("tenant-a", null, "Directory", "selector", "hash");
        ScimResourceLink missing = new ScimResourceLink(source.getId(), "tenant-a", "User", "missing-ext", "missing", "[]");
        ScimResourceLink mismatch = new ScimResourceLink(source.getId(), "tenant-a", "User", "mismatch-ext", "user-1", "[]");
        Principal principal = mock(Principal.class);
        when(executionTenant.require()).thenReturn("tenant-a");
        when(sources.findByIdAndTenantId(source.getId(), "tenant-a")).thenReturn(Optional.of(source));
        when(links.findBySourceId(source.getId())).thenReturn(List.of(missing, mismatch));
        when(principals.findByIdAndTenantId("missing", "tenant-a")).thenReturn(Optional.empty());
        when(principals.findByIdAndTenantId("user-1", "tenant-a")).thenReturn(Optional.of(principal));
        when(principal.getScimSourceId()).thenReturn(UUID.randomUUID());

        var result = new ScimReconciliationService(sources, links, principals, mock(GroupRepository.class), audit, executionTenant)
                .check("tenant-a", source.getId(), null);

        assertThat(result.sourceLinkedUsers()).isEqualTo(2);
        assertThat(result.missingBackingResources()).containsExactly("User:missing:missing-ext");
        assertThat(result.ownershipMismatches()).containsExactly("User:user-1");
        verify(audit).logRequired(any(), any(), any(), any(), any(), any(), any(), any());
    }
}
