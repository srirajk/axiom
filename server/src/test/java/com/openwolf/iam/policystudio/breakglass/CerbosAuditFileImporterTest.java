package com.openwolf.iam.policystudio.breakglass;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import java.util.HashSet;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class CerbosAuditFileImporterTest {

    @Test
    void importsEveryBatchedResourceActionExactlyOnceAndSkipsAccessLines() {
        BreakGlassDecisionEventRepository repo = mock(BreakGlassDecisionEventRepository.class);
        BreakGlassBundleGrantRepository bundleGrants = mock(BreakGlassBundleGrantRepository.class);
        when(bundleGrants.existsByBundleId("b_active")).thenReturn(true);
        Set<String> stored = new HashSet<>();
        when(repo.existsById(any())).thenAnswer(call -> stored.contains(call.getArgument(0)));
        when(repo.save(any())).thenAnswer(call -> {
            BreakGlassDecisionEvent event = call.getArgument(0);
            stored.add(event.getEventId());
            return event;
        });
        CerbosAuditFileImporter importer = new CerbosAuditFileImporter(new ObjectMapper(), repo, bundleGrants, "");
        String decision = """
                {"log.kind":"decision","callId":"call-7","timestamp":"2026-07-17T10:05:00Z",
                 "checkResources":{
                   "inputs":[
                     {"principal":{"id":"alice","roles":["platform_admin"],"attr":{"tenant_id":"acme"}},
                      "resource":{"kind":"agent","id":"a-1","policyVersion":"b_active",
                                  "attr":{"tenant_id":"acme"}},"actions":["register"]},
                     {"principal":{"id":"alice","roles":["platform_admin"],"attr":{"tenant_id":"acme"}},
                      "resource":{"kind":"agent","id":"a-2","policyVersion":"b_active",
                                  "attr":{"tenant_id":"acme"}},"actions":["invoke"]}],
                   "outputs":[
                     {"resourceId":"a-1","actions":{"register":{"effect":"EFFECT_ALLOW",
                       "policy":"resource.agent.vb_active/acme"}}},
                     {"resourceId":"a-2","actions":{"invoke":{"effect":"EFFECT_DENY",
                       "policy":"resource.agent.vb_active/acme"}}}]}}
                """;

        assertThat(importer.importLine(decision)).isEqualTo(2);
        assertThat(importer.importLine(decision)).as("composite ids make a file rescan idempotent").isZero();
        assertThat(importer.importLine("{\"log\":{\"kind\":\"access\"}}" )).isZero();
        assertThat(stored).containsExactlyInAnyOrder("call-7:a-1:register", "call-7:a-2:invoke");
    }
}
