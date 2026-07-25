package com.openwolf.iam.policystudio;

import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * C3.3 — every intent-implied ALLOW is mechanically fanned into exactly three negative probes
 * (cross-tenant, wrong-segment, missing-attribute), each expected DENY. These are the negatives a
 * self-consistent co-generated suite would never write.
 */
class NegativeProbeInjectionTest {

    private final NegativeProbeInjector injector = new NegativeProbeInjector();
    private final ProbeAttributes attrs = C3TestGenFixtures.probeAttributes();
    private final ManifestVocabulary vocab = PolicyStudioFixtures.agentVocab();

    private Expectation allow(Set<String> roles, String action, String classification) {
        return new Expectation(roles, "acme", "acme",
                Map.of("data_classification", classification), action, Effect.ALLOW,
                ProbeKind.POSITIVE, "allow_" + String.join("+", roles) + "_" + action);
    }

    @Test
    void everyAllowGetsCrossTenantWrongSegmentMissingAttrProbes() {
        TestExpectationSet base = TestExpectationSet.of(List.of(
                allow(Set.of("chat_user"), "invoke", "internal"),
                allow(Set.of("relationship_manager"), "invoke", "confidential")));

        TestExpectationSet injected = injector.inject(base, attrs, vocab);

        // 2 positives preserved + 3 probes each = 8
        assertThat(injected.expectations()).hasSize(2 + 2 * NegativeProbeInjector.PROBES_PER_ALLOW);
        assertThat(injected.countOfKind(ProbeKind.POSITIVE)).isEqualTo(2);
        assertThat(injected.countOfKind(ProbeKind.CROSS_TENANT)).isEqualTo(2);
        assertThat(injected.countOfKind(ProbeKind.WRONG_SEGMENT)).isEqualTo(2);
        assertThat(injected.countOfKind(ProbeKind.MISSING_ATTRIBUTE)).isEqualTo(2);

        // Every probe expects DENY.
        assertThat(injected.expectations().stream()
                .filter(e -> e.kind() != ProbeKind.POSITIVE)
                .allMatch(e -> e.expected() == Effect.DENY)).isTrue();
    }

    @Test
    void crossTenantProbeHomesResourceInADifferentTenant() {
        Expectation p = allow(Set.of("chat_user"), "invoke", "internal");
        TestExpectationSet injected = injector.inject(TestExpectationSet.of(List.of(p)), attrs, vocab);

        Expectation ct = injected.expectations().stream()
                .filter(e -> e.kind() == ProbeKind.CROSS_TENANT).findFirst().orElseThrow();
        assertThat(ct.isCrossTenant()).isTrue();
        assertThat(ct.resourceTenant()).isNotEqualTo(ct.principalTenant());
        assertThat(ct.action()).isEqualTo("invoke");
        assertThat(ct.principalRoles()).containsExactly("chat_user");
    }

    @Test
    void wrongSegmentProbeSwapsInAnUnsanctionedClassification() {
        Expectation p = allow(Set.of("chat_user"), "invoke", "internal");
        TestExpectationSet injected = injector.inject(TestExpectationSet.of(List.of(p)), attrs, vocab);

        Expectation ws = injected.expectations().stream()
                .filter(e -> e.kind() == ProbeKind.WRONG_SEGMENT).findFirst().orElseThrow();
        Object cls = ws.resourceAttrs().get("data_classification");
        assertThat(cls).isNotEqualTo("internal");
        assertThat(vocab.classifications()).contains((String) cls);
    }

    @Test
    void missingAttributeProbeOmitsTheGuardAttribute() {
        Expectation p = allow(Set.of("chat_user"), "invoke", "internal");
        TestExpectationSet injected = injector.inject(TestExpectationSet.of(List.of(p)), attrs, vocab);

        Expectation ma = injected.expectations().stream()
                .filter(e -> e.kind() == ProbeKind.MISSING_ATTRIBUTE).findFirst().orElseThrow();
        assertThat(ma.resourceAttrs()).doesNotContainKey("data_classification");
    }

    @Test
    void explicitDenyRestrictionsAreNotFannedOut() {
        Expectation restriction = new Expectation(Set.of("chat_user"), "acme", "acme",
                Map.of(), "invoke_membership", Effect.DENY, ProbeKind.POSITIVE, "deny_membership");
        TestExpectationSet injected = injector.inject(
                TestExpectationSet.of(List.of(restriction)), attrs, vocab);
        // No probes added for a DENY restriction (only ALLOWs are fanned).
        assertThat(injected.expectations()).hasSize(1);
    }
}
