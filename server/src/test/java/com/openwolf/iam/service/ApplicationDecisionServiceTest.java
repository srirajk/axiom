package com.openwolf.iam.service;

import com.openwolf.iam.dto.ApplicationDecisionBatchRequest;
import com.openwolf.iam.dto.ApplicationDecisionItem;
import com.openwolf.iam.dto.ApplicationDecisionResource;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class ApplicationDecisionServiceTest {
    private final ApplicationAccessService access = mock(ApplicationAccessService.class);
    private final ApplicationDecisionService service = new ApplicationDecisionService(access, mock(AuditService.class));

    @Test
    void preservesScopedAndCosignFrozenTuples() {
        when(access.decisionAuthority("tenant-a", APP, "subject-a")).thenReturn(Optional.of(authority(
                Map.of("edit", "scoped", "approve", "cosign"), Map.of("scopes", Map.of("domain", List.of("banking"))))));
        var response = service.decide("tenant-a", "subject-a", APP, request(
                item("scoped", "edit", "banking"), item("cosign", "approve", "banking")), null);

        assertThat(response.results()).extracting(result -> result.decisionKey() + ":" + result.outcome()
                        + ":" + result.allowed() + ":" + result.effect())
                .containsExactly("scoped:permit:true:scoped", "cosign:require_cosign:false:cosign");
    }

    @Test
    void scopedPermissionFailsClosedWithoutApplicableScope() {
        when(access.decisionAuthority("tenant-a", APP, "subject-a")).thenReturn(Optional.of(authority(
                Map.of("edit", "scoped"), Map.of())));
        var response = service.decide("tenant-a", "subject-a", APP, request(item("scoped", "edit", "banking")), null);

        assertThat(response.results().getFirst().reasonCodes()).containsExactly("DENY_SCOPE");
    }

    @Test
    void strongestApplicationRoleEffectUsesFrozenPrecedence() {
        assertThat(ApplicationAccessService.mostPermissiveEffect("read", "cosign")).isEqualTo("cosign");
        assertThat(ApplicationAccessService.mostPermissiveEffect("scoped", "allow")).isEqualTo("allow");
    }

    private static final UUID APP = UUID.fromString("00000000-0000-0000-0000-000000000001");

    private static ApplicationAccessService.DecisionAuthority authority(Map<String, String> effects, Map<String, Object> attributes) {
        return new ApplicationAccessService.DecisionAuthority("sample-app", 7L, Set.of("reader"), effects, attributes, "policy-v1");
    }

    private static ApplicationDecisionBatchRequest request(ApplicationDecisionItem... items) {
        return new ApplicationDecisionBatchRequest("1.0", "tenant-a", "subject-a", "request-1", List.of(items));
    }

    private static ApplicationDecisionItem item(String key, String permission, String domain) {
        return new ApplicationDecisionItem(key, permission,
                new ApplicationDecisionResource("record", "record-1", "tenant-a", domain, null, Map.of(), "ordinary"), Map.of());
    }
}
