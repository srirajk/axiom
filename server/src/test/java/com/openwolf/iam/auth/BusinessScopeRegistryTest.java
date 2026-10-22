package com.openwolf.iam.auth;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class BusinessScopeRegistryTest {
    @Test
    void exposesOnlyDeploymentApprovedBusinessScopes() {
        BusinessScopeRegistry registry = new BusinessScopeRegistry(
                "cards:incident.read,wealth:portfolio.review");
        assertThat(registry.isApproved("cards:incident.read")).isTrue();
        assertThat(registry.isApproved("cards:incident.write")).isFalse();
    }

    @Test
    void refusesReservedOrMalformedConfiguration() {
        assertThatThrownBy(() -> new BusinessScopeRegistry("axiom.platform-authz.decide"))
                .isInstanceOf(IllegalStateException.class);
        assertThatThrownBy(() -> new BusinessScopeRegistry("wildcard-*"))
                .isInstanceOf(IllegalStateException.class);
    }

    @Test
    void customNamesNeedTheNormalizedSyntaxAndNoReservedFirstSegment() {
        for (String ok : java.util.List.of("quickstart:invoke", "orders.read", "emailer:send", "cards:incident.read",
                "a1-b:c2")) {
            assertThat(BusinessScopeRegistry.isValidCustomName(ok)).as(ok).isTrue();
        }
        for (String bad : java.util.List.of("", "noseparator", "Quickstart:Invoke", "axiom:x", "axiom.platform:x",
                "urn:ietf:params", "openid:x", "offline_access", "profile:read", "email:read", "roles:x", "trailing:",
                ":leading", "a b:c", "a*:b", "1abc:x", "x:" + "y".repeat(130))) {
            assertThat(BusinessScopeRegistry.isValidCustomName(bad)).as(bad).isFalse();
        }
        assertThat(BusinessScopeRegistry.isValidCustomName(null)).isFalse();
    }

    @Test
    void tenantApprovalIsTheConfiguredBaselinePlusThatTenantsCatalogOnly() {
        BusinessScopeRegistry registry = new BusinessScopeRegistry("cards:incident.read");
        com.openwolf.iam.scopes.TenantBusinessScopeCatalog catalog =
                org.mockito.Mockito.mock(com.openwolf.iam.scopes.TenantBusinessScopeCatalog.class);
        org.mockito.Mockito.when(catalog.contains("tenant-a", "quickstart:invoke")).thenReturn(true);
        registry.setCatalog(catalog);
        assertThat(registry.isApproved("tenant-a", "cards:incident.read")).isTrue();
        assertThat(registry.isApproved("tenant-b", "cards:incident.read")).isTrue();
        assertThat(registry.isApproved("tenant-a", "quickstart:invoke")).isTrue();
        assertThat(registry.isApproved("tenant-b", "quickstart:invoke")).isFalse();
        assertThat(registry.isApproved(null, "quickstart:invoke")).isFalse();
        assertThat(registry.isApproved("quickstart:invoke")).as("static check ignores tenant catalogs").isFalse();
        assertThat(registry.approvedScopes()).containsExactly("cards:incident.read");
    }
}
