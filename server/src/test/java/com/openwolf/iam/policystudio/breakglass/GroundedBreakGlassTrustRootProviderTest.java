package com.openwolf.iam.policystudio.breakglass;

import com.openwolf.iam.policystudio.BaseCeiling;
import com.openwolf.iam.policystudio.BundleSnapshot;
import com.openwolf.iam.policystudio.CanonicalPolicyWriter;
import com.openwolf.iam.policystudio.ConsequenceFixtureMatrix;
import com.openwolf.iam.policystudio.ManifestVocabulary;
import com.openwolf.iam.policystudio.StudioGroundingSnapshot;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class GroundedBreakGlassTrustRootProviderTest {

    @Test
    void emptyServerAllowlistFailsClosed() {
        GroundedBreakGlassTrustRootProvider provider =
                new GroundedBreakGlassTrustRootProvider((tenant, resource) -> snapshot(tenant), "");

        assertThatThrownBy(() -> provider.resolve("acme", "agent"))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("no trusted break-glass allowlist")
                .hasMessageContaining("fail-closed");
    }

    @Test
    void onlyExactConfiguredTenantResourceActionsAreReturned() {
        GroundedBreakGlassTrustRootProvider provider = new GroundedBreakGlassTrustRootProvider(
                (tenant, resource) -> snapshot(tenant),
                "acme|agent|register,beta|agent|invoke,acme|relationship|view");

        BreakGlassTrustRootProvider.TrustRoots roots = provider.resolve("acme", "agent");

        assertThat(roots.allowlist().resources()).containsExactly("agent");
        assertThat(roots.allowlist().actions()).containsExactly("register");
        assertThat(roots.vocabulary().actions()).contains("register", "invoke");
    }

    private static StudioGroundingSnapshot snapshot(String tenant) {
        ManifestVocabulary vocabulary = new ManifestVocabulary("agent", Set.of("register", "invoke"),
                Set.of(), Set.of(), Set.of("platform_admin"), Set.of());
        BaseCeiling ceiling = new BaseCeiling("agent", Set.of(
                new BaseCeiling.Tuple("register", "platform_admin"),
                new BaseCeiling.Tuple("invoke", "platform_admin")), true, Set.of());
        return new StudioGroundingSnapshot(tenant, vocabulary, ceiling,
                ConsequenceFixtureMatrix.of(List.of()), BundleSnapshot.of(null, ceiling, new CanonicalPolicyWriter()),
                List.of("test"));
    }
}
