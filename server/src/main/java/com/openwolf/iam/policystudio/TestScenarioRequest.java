package com.openwolf.iam.policystudio;

/**
 * The <b>complete</b> input handed to the independent test-scenario oracle (Axiom Story C3.1). This
 * type is the structural embodiment of the moat: it carries ONLY the author's natural-language
 * intent plus the tenant's manifest vocabulary, author scope, and base ceiling — the same facts that
 * <em>preceded</em> generation. It has <b>no YAML field, no {@link PolicyIR}, and no reference to any
 * generated artifact</b>, so an oracle built over this request cannot predicate its expectations on
 * the candidate policy's behaviour. If someone tries to "improve the tests" by wiring the generated
 * YAML in here, they must add a field of a policy-artifact type — which {@code TestGenIsolationArchTest}
 * turns red.
 *
 * <p>Contrast with {@link PolicyAuthoringRequest}: that request is the generator's input; this is the
 * oracle's input. They share the grounding facts (vocabulary/scope/ceiling) but the oracle's input is
 * a strict subset that can never contain a policy artifact. Two processes, two prompts, one-way facts.
 *
 * @param intent      the author's natural-language policy intent (the ONLY behavioural signal)
 * @param vocabulary  the closed manifest vocabulary the oracle may reference (roles/actions/…)
 * @param authorScope the author's tenant scope (used to home principals/resources in probes)
 * @param baseCeiling the immutable base ceiling (used to reason about fall-through and to home probes)
 */
public record TestScenarioRequest(
        String intent,
        ManifestVocabulary vocabulary,
        TenantScope authorScope,
        BaseCeiling baseCeiling) {

    public TestScenarioRequest {
        if (intent == null || intent.isBlank()) {
            throw new IllegalArgumentException("intent must be set");
        }
        if (vocabulary == null || authorScope == null || baseCeiling == null) {
            throw new IllegalArgumentException("vocabulary, authorScope and baseCeiling must be set");
        }
        if (!vocabulary.resourceKind().equals(baseCeiling.resourceKind())) {
            throw new IllegalArgumentException(
                    "vocabulary resourceKind '" + vocabulary.resourceKind()
                            + "' != base ceiling resourceKind '" + baseCeiling.resourceKind() + "'");
        }
    }

    /**
     * Derive the oracle's input from the same grounding facts the generator received, <em>dropping</em>
     * everything downstream of the intent. This is the ONLY sanctioned way to build the oracle input
     * from an authoring request, and it is a lossy, one-way projection: the returned request cannot
     * carry the proposal, the IR, or the canonical YAML even if the caller wanted it to.
     */
    public static TestScenarioRequest fromAuthoring(PolicyAuthoringRequest authoring) {
        return new TestScenarioRequest(
                authoring.intent(),
                authoring.vocabulary(),
                authoring.authorScope(),
                authoring.baseCeiling());
    }
}
