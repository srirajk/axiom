package com.openwolf.iam.repository;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;

import static org.assertj.core.api.Assertions.assertThat;

class CiamMigrationContractTest {
    @Test
    void schemaPinsTenantScopedGrantsAndAppendOnlyLifecycleEvidence() throws Exception {
        try (var stream = getClass().getResourceAsStream(
                "/db/migration/V28__ciam_customer_lifecycle.sql")) {
            assertThat(stream).isNotNull();
            String sql = new String(stream.readAllBytes(), StandardCharsets.UTF_8);
            assertThat(sql).contains("FOREIGN KEY (tenant_id, customer_id)")
                    .contains("FOREIGN KEY (tenant_id, agent_workload_id)")
                    .contains("ciam_lifecycle_events_no_update")
                    .contains("ciam_lifecycle_events_no_delete")
                    .doesNotContain("INSERT INTO");
        }
    }
}
