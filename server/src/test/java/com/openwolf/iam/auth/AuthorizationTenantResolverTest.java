package com.openwolf.iam.auth;

import com.openwolf.iam.entity.Principal;
import com.openwolf.iam.repository.PrincipalRepository;
import com.openwolf.iam.service.TenantApplicationService;
import org.junit.jupiter.api.Test;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class AuthorizationTenantResolverTest {
    private final PrincipalRepository principals = mock(PrincipalRepository.class);
    private final TenantApplicationService applications = mock(TenantApplicationService.class);
    private final AuthorizationTenantResolver resolver = new AuthorizationTenantResolver(principals, applications);

    @Test
    void resolvesOnlyAnActivePrincipal() {
        Principal active = new Principal("user-1", "tenant-a", "alice", "alice@example.test",
                "hash", true, "{}");
        when(principals.findById("user-1")).thenReturn(Optional.of(active));
        when(principals.findByUsername("user-1")).thenReturn(Optional.empty());
        when(applications.activeAuthority("user-1")).thenReturn(Optional.empty());

        assertEquals("tenant-a", resolver.resolve("user-1"));
    }

    @Test
    void refusesInactivePrincipalBeforeAuthorizationStateIsPersisted() {
        Principal inactive = new Principal("user-1", "tenant-a", "alice", "alice@example.test",
                "hash", false, "{}");
        when(principals.findById("user-1")).thenReturn(Optional.of(inactive));
        when(principals.findByUsername("user-1")).thenReturn(Optional.empty());
        when(applications.activeAuthority("user-1")).thenReturn(Optional.empty());

        assertThrows(IllegalStateException.class, () -> resolver.resolve("user-1"));
    }
}
