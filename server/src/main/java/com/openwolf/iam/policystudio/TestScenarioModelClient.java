package com.openwolf.iam.policystudio;

/**
 * Authoring-plane seam to the INDEPENDENT test oracle (Axiom Story C3 — the moat).
 *
 * <p>This is a <b>different process and a different prompt</b> from
 * {@link PolicyAuthoringModelClient}. Where the authoring client proposes policy YAML, this client
 * proposes only the <em>expected decisions</em> the author's intent implies. Its single parameter is
 * a {@link TestScenarioRequest}, which by construction has no YAML field and no path to the candidate
 * policy — so an implementation, however it is built (seeded stub or, later, an LLM), cannot ground
 * its expectations in the generated artifact. That structural absence is the fix to the circular-trust
 * / oracle problem: a wrong policy can no longer manufacture self-consistent green tests, because the
 * tests are not derived from it.
 *
 * <p><b>Boundary invariant (C3.1, ArchUnit-enforced by {@code TestGenIsolationArchTest} and
 * {@code PolicyAuthoringBoundaryArchTest}):</b> this interface is authoring-plane only and is
 * structurally unreachable from runtime enforcement. Additionally, neither this interface nor
 * {@link TestScenarioRequest} may reference {@link PolicyIR} or {@link StudioGenerationResult} — the
 * arch test fails red if a YAML/IR-shaped input is wired in "to improve the tests".
 */
public interface TestScenarioModelClient {

    /**
     * Propose the set of expected authorization decisions the request's intent implies, grounded in
     * the supplied manifest vocabulary. The returned set is the POSITIVE oracle (before negative
     * probes are mechanically injected). It must be derived from the intent alone — never from any
     * candidate policy.
     */
    TestExpectationSet proposeExpectations(TestScenarioRequest request);
}
