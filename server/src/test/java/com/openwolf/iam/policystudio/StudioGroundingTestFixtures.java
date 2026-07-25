package com.openwolf.iam.policystudio;

import com.openwolf.iam.policystudio.lifecycle.PolicyBundleRepository;
import com.openwolf.iam.tenancy.ActiveTenantDirectory;
import com.openwolf.iam.tenancy.ActiveTenantRepository;

import java.io.IOException;
import java.lang.reflect.Proxy;
import java.nio.file.Files;
import java.nio.file.Path;

/** Explicit per-tenant deployment grounding used by Policy Studio tests. */
public final class StudioGroundingTestFixtures {

    private StudioGroundingTestFixtures() {}

    public static void writeTenantDeployment(Path root, String tenantId) throws IOException {
        Path tenantDir = root.resolve(tenantId);
        Files.createDirectories(tenantDir);
        Files.writeString(tenantDir.resolve("domain-segment-map.yaml"), """
                tenant: %s
                domain_segment_map:
                  wealth-management: wealth
                  asset-servicing: servicing
                  insurance: insurance
                classification_ladder:
                  - internal
                  - confidential
                  - confidential-pii
                """.formatted(tenantId));
    }

    public static ActiveTenantDirectory emptyTenantDirectory() {
        return new ActiveTenantDirectory(emptyRepository(ActiveTenantRepository.class));
    }

    public static PolicyBundleRepository emptyBundleRepository() {
        return emptyRepository(PolicyBundleRepository.class);
    }

    private static <T> T emptyRepository(Class<T> repositoryType) {
        Object proxy = Proxy.newProxyInstance(repositoryType.getClassLoader(), new Class<?>[] {repositoryType},
                (ignored, method, args) -> {
                    if (method.getReturnType().equals(boolean.class)) {
                        return false;
                    }
                    if (method.getReturnType().equals(long.class)) {
                        return 0L;
                    }
                    if (method.getReturnType().equals(int.class)) {
                        return 0;
                    }
                    if (java.util.Optional.class.isAssignableFrom(method.getReturnType())) {
                        return java.util.Optional.empty();
                    }
                    if (java.util.List.class.isAssignableFrom(method.getReturnType())) {
                        return java.util.List.of();
                    }
                    return null;
                });
        return repositoryType.cast(proxy);
    }
}
