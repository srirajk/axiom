package com.openwolf.iam.policystudio.lifecycle;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class BundleContentReaderTenantWideTest {

    @Test
    void selectsTheRequestedResourceChildFromATenantWideBundle() {
        String content = """
                bundle-v1
                tenant=acme
                FILE:policies/agent@acme.yaml
                agent-child
                FILE:policies/relationship@acme.yaml
                relationship-child
                MANIFESTS:
                TESTS:
                """;

        assertThat(BundleContentReader.tenantChildYaml(content, "agent", "acme"))
                .contains("agent-child\n");
        assertThat(BundleContentReader.tenantChildYaml(content, "relationship", "acme"))
                .contains("relationship-child\n");
        assertThat(BundleContentReader.tenantChildYaml(content, "domain", "acme")).isEmpty();
    }
}
