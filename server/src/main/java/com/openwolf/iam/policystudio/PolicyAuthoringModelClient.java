package com.openwolf.iam.policystudio;

/**
 * Authoring-only seam to the LLM that <em>proposes</em> Cerbos policy YAML from a
 * natural-language authoring intent (Axiom Story C2).
 *
 * <p><b>The LLM only PROPOSES; it is never a control.</b> Everything a proposal claims is
 * re-derived deterministically downstream by {@link PolicyYamlParser} +
 * {@link GeneratedPolicyValidator} + {@link CerbosCompileGate}. A proposal that escapes the
 * author's tenant subtree, invents vocabulary, drops a base-ceiling tuple, or fails to compile is
 * rejected before anything is stored — regardless of how confident the model was.
 *
 * <p><b>Boundary invariant (C2.5, ArchUnit-enforced by
 * {@code PolicyAuthoringBoundaryArchTest}):</b> this interface and every
 * {@code com.openwolf.iam.policystudio} generation service are <em>authoring-plane</em> only.
 * They must NEVER be injected into, imported by, or otherwise reachable from runtime
 * enforcement code — token verification, the Cerbos entitlement path, coverage enforcement, or
 * runtime invocation. Serving components (separate modules with no dependency on iam-service) can
 * not reach this type at all; within iam-service the ArchUnit rule proves the same.
 */
public interface PolicyAuthoringModelClient {

    /**
     * Ask the model to propose a Cerbos v1 resource-policy YAML document for the request's intent,
     * grounded in the supplied manifest vocabulary and tenant/base-ceiling context.
     *
     * @return the model's raw proposed YAML text. This text is NEVER stored or trusted directly —
     *         the caller parses it into a typed IR, validates it, and re-materialises canonical
     *         YAML from the validated IR. A well-behaved implementation performs no side effects.
     */
    String proposePolicyYaml(PolicyAuthoringRequest request);
}
