package com.openwolf.iam.policystudio.breakglass;

import com.openwolf.iam.policystudio.PolicyIR;
import com.openwolf.iam.policystudio.TenantScope;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class BreakGlassConditionPreservingMergeTest {

    private final BreakGlassPolicyCompiler compiler = new BreakGlassPolicyCompiler();

    @Test
    void splittingExactTuplePreservesOrdinaryConditionOnEveryOriginalCombination() {
        String originalCondition = "R.attr.classification == \"restricted\"";
        PolicyIR current = child(List.of(new PolicyIR.Rule(
                List.of("register", "invoke"), "EFFECT_ALLOW", List.of("platform_admin", "auditor"), List.of(),
                Map.of("match", Map.of("expr", originalCondition)))));

        PolicyIR merged = compiler.compile(grant("register", Instant.parse("2026-07-17T10:00:00Z"),
                Instant.parse("2026-07-17T10:30:00Z")), BreakGlassFixtures.ceiling(), current);

        assertThat(merged.rules()).anySatisfy(rule -> {
            assertThat(rule.actions()).containsExactly("invoke");
            assertThat(rule.roles()).containsExactly("platform_admin", "auditor");
            assertThat(rule.conditionText()).contains(originalCondition);
        });
        assertThat(merged.rules()).anySatisfy(rule -> {
            assertThat(rule.actions()).containsExactly("register");
            assertThat(rule.roles()).containsExactly("auditor");
            assertThat(rule.conditionText()).contains(originalCondition);
        });
        assertThat(merged.rules()).filteredOn(rule -> rule.actions().contains("register")
                        && rule.roles().contains("platform_admin"))
                .allSatisfy(rule -> assertThat(rule.condition()).isNotNull());
        assertThat(merged.rules()).anySatisfy(rule -> {
            assertThat(rule.actions()).containsExactly("register");
            assertThat(rule.roles()).containsExactly("platform_admin");
            assertThat(rule.conditionText())
                    .contains(originalCondition)
                    .contains("now() < timestamp(\"2026-07-17T10:00:00Z\") || "
                            + "now() >= timestamp(\"2026-07-17T10:30:00Z\")");
        });
    }

    @Test
    void sequentialGrantRetainsBothConditionsFromEarlierBreakGlassWindow() {
        PolicyIR baseline = child(List.of(new PolicyIR.Rule(
                List.of("register"), "EFFECT_DENY", List.of("platform_admin"), List.of(),
                Map.of("match", Map.of("expr", "R.attr.incident_open == false")))));
        BreakGlassGrant firstGrant = grant("register", Instant.parse("2026-07-17T10:00:00Z"),
                Instant.parse("2026-07-17T10:30:00Z"));
        PolicyIR first = compiler.compile(firstGrant, BreakGlassFixtures.ceiling(), baseline);

        BreakGlassGrant secondGrant = grant("register", Instant.parse("2026-07-17T10:05:00Z"),
                Instant.parse("2026-07-17T10:20:00Z"));
        PolicyIR second = compiler.compile(secondGrant, BreakGlassFixtures.ceiling(), first);

        String firstAllow = BreakGlassPolicyCompiler.activeWindow(firstGrant);
        String firstDeny = BreakGlassPolicyCompiler.outsideWindow(firstGrant);
        String secondOutside = BreakGlassPolicyCompiler.outsideWindow(secondGrant);

        assertThat(second.rules()).anySatisfy(rule -> assertThat(rule.conditionText())
                .contains(firstAllow).contains(secondOutside));
        assertThat(second.rules()).anySatisfy(rule -> assertThat(rule.conditionText())
                .contains(firstDeny).contains(secondOutside));
        assertThat(second.rules()).filteredOn(rule -> rule.actions().contains("register")
                        && rule.roles().contains("platform_admin"))
                .allSatisfy(rule -> assertThat(rule.condition()).isNotNull());
    }

    @Test
    void targetActionDerivedRoleRuleFailsClosedWithoutTrustedParentExpansion() {
        PolicyIR current = child(List.of(new PolicyIR.Rule(
                List.of("register"), "EFFECT_DENY", List.of(), List.of("tenant_platform_admin"),
                Map.of("match", Map.of("expr", "R.attr.incident_open == false")))));

        assertThatThrownBy(() -> compiler.compile(
                grant("register", Instant.parse("2026-07-17T10:00:00Z"),
                        Instant.parse("2026-07-17T10:30:00Z")),
                BreakGlassFixtures.ceiling(), current))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("derivedRoles")
                .hasMessageContaining("parent-role expansion is required");
    }

    private static PolicyIR child(List<PolicyIR.Rule> rules) {
        return new PolicyIR("api.cerbos.dev/v1", "default", "agent", "acme",
                "SCOPE_PERMISSIONS_REQUIRE_PARENTAL_CONSENT_FOR_ALLOWS", List.of(), rules);
    }

    private static BreakGlassGrant grant(String action, Instant issuedAt, Instant expiresAt) {
        return new BreakGlassGrant(TenantScope.of("acme"), "agent", action, "platform_admin",
                issuedAt, expiresAt, "incident", "alice");
    }
}
