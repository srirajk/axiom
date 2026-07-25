package com.openwolf.iam.policystudio;

import java.util.List;
import java.util.Map;

/**
 * An ordered, immutable set of {@link Expectation}s — the independently-generated test oracle for one
 * authoring turn (Axiom Story C3), before and after negative-probe injection. It can render itself to
 * a Cerbos-style {@code _test.yaml} document (the C3 deliverable "emits {@code _test.yaml}
 * expectations") so the exact scenarios run against a candidate are inspectable and checked in.
 */
public record TestExpectationSet(List<Expectation> expectations) {

    public TestExpectationSet {
        expectations = List.copyOf(expectations);
    }

    public static TestExpectationSet of(List<Expectation> expectations) {
        return new TestExpectationSet(expectations);
    }

    /** The intent-implied ALLOW expectations — the ones the probe injector fans out. */
    public List<Expectation> allows() {
        return expectations.stream()
                .filter(e -> e.kind() == ProbeKind.POSITIVE && e.expected() == Effect.ALLOW)
                .toList();
    }

    public long countOfKind(ProbeKind kind) {
        return expectations.stream().filter(e -> e.kind() == kind).count();
    }

    /**
     * Render a Cerbos test-suite YAML for the given resource kind. This is a faithful, human-readable
     * emission of the oracle — the same expectations {@link PolicyExpectationEvaluator} checks — so an
     * operator can diff the intent's requirements against what a candidate actually decides.
     */
    public String renderTestYaml(String resourceKind) {
        StringBuilder sb = new StringBuilder();
        sb.append("# GENERATED FROM INTENT ONLY — never from candidate policy YAML (Axiom C3 moat).\n");
        sb.append("name: IndependentIntentOracle\n");
        sb.append("description: Expected decisions derived from the author's intent + injected negative probes.\n");
        sb.append("tests:\n");
        int i = 0;
        for (Expectation e : expectations) {
            sb.append("  - name: \"").append(e.label()).append("\"\n");
            sb.append("    input:\n");
            sb.append("      principals: [p").append(i).append("]\n");
            sb.append("      resources: [r").append(i).append("]\n");
            sb.append("      actions: [").append(e.action()).append("]\n");
            sb.append("    expected:\n");
            sb.append("      - principal: p").append(i)
                    .append("  # roles=").append(e.principalRoles())
                    .append(" tenant=").append(e.principalTenant()).append("\n");
            sb.append("        resource: r").append(i)
                    .append("  # kind=").append(resourceKind)
                    .append(" tenant=").append(e.resourceTenant())
                    .append(" attrs=").append(renderAttrs(e.resourceAttrs())).append("\n");
            sb.append("        actions: {").append(e.action()).append(": EFFECT_")
                    .append(e.expected()).append("}   # probe=").append(e.kind()).append("\n");
            i++;
        }
        return sb.toString();
    }

    private static String renderAttrs(Map<String, Object> attrs) {
        return attrs.isEmpty() ? "{}" : attrs.toString();
    }
}
