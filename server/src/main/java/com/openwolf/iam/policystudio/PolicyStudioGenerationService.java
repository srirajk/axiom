package com.openwolf.iam.policystudio;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.nio.file.Path;
import java.util.List;

/**
 * The C2 generation pipeline (authoring plane only). Orchestrates the controls in order:
 *
 * <pre>
 *   intent + manifest vocabulary + author scope + base ceiling
 *        │  (1) model PROPOSES                     PolicyAuthoringModelClient
 *        ▼
 *   raw YAML text  ──(2) parse (reject aliases/tags/non-resource-policy)──▶ typed IR
 *        │  PolicyYamlParser
 *        ▼
 *   (3) deterministic gate (scope subtree, vocabulary, finiteness, backstop, totality, identity)
 *        │  GeneratedPolicyValidator            ← THE control; the model is never trusted
 *        ▼
 *   (4) materialise CANONICAL yaml from the IR (never the model text)   CanonicalPolicyWriter
 *        ▼
 *   (5) compile candidate + immutable base bundle with the pinned Cerbos  CerbosCompileGate
 *        ▼
 *   ACCEPTED → store canonical yaml     |    any failure → REJECTED, nothing stored
 * </pre>
 *
 * <b>Boundary (C2.5):</b> this service and its collaborators are authoring-plane; the ArchUnit
 * rule proves no runtime-enforcement class in iam-service depends on them, and serving components
 * cannot bypass the authoring gate.
 */
@Service
public class PolicyStudioGenerationService {

    private static final Logger log = LoggerFactory.getLogger(PolicyStudioGenerationService.class);

    private final PolicyAuthoringModelClient modelClient;
    private final PolicyYamlParser parser;
    private final GeneratedPolicyValidator validator;
    private final CanonicalPolicyWriter writer;
    private final CerbosCompileGate compileGate;
    private final String baseBundleDir;

    public PolicyStudioGenerationService(
            PolicyAuthoringModelClient modelClient,
            PolicyYamlParser parser,
            GeneratedPolicyValidator validator,
            CanonicalPolicyWriter writer,
            CerbosCompileGate compileGate,
            @Value("${iam.policy-studio.base-bundle-dir:/app/platform-policy/policies}") String baseBundleDir) {
        this.modelClient = modelClient;
        this.parser = parser;
        this.validator = validator;
        this.writer = writer;
        this.compileGate = compileGate;
        this.baseBundleDir = baseBundleDir;
    }

    /**
     * Run the full pipeline for one authoring request. Never throws for a bad proposal — a bad
     * proposal is a normal REJECTED outcome; nothing is stored on rejection.
     */
    public StudioGenerationResult generate(PolicyAuthoringRequest request) {
        // (1) model proposes
        String proposed;
        try {
            proposed = modelClient.proposePolicyYaml(request);
        } catch (RuntimeException e) {
            log.warn("policy authoring model call failed", e);
            return StudioGenerationResult.rejected(StudioGenerationResult.Stage.PARSE,
                    List.of("model proposal failed: " + e.getMessage()));
        }

        // (2) parse into typed IR — rejects aliases/custom tags/non-resource-policy
        PolicyIR ir;
        try {
            ir = parser.parse(proposed);
        } catch (PolicyParseException e) {
            return StudioGenerationResult.rejected(StudioGenerationResult.Stage.PARSE, List.of(e.getMessage()));
        }

        // (3) deterministic gate
        GeneratedPolicyValidator.Result result = validator.validate(ir, request);
        if (!result.accepted()) {
            return StudioGenerationResult.rejected(StudioGenerationResult.Stage.VALIDATE, result.violations());
        }

        // (4) canonicalise from the validated IR (never store the model's raw text)
        String canonical = writer.write(ir);

        // (5) compile candidate + immutable base bundle with the pinned Cerbos
        if (!compileGate.isAvailable()) {
            log.warn("Cerbos compile gate unavailable — candidate passed the deterministic gate but "
                    + "was NOT compile-verified; not marking as compile-approved.");
            return new StudioGenerationResult(false, canonical,
                    List.of("compile gate unavailable — refusing to accept uncompiled candidate"),
                    StudioGenerationResult.Stage.COMPILE_SKIPPED);
        }
        String candidateFile = "generated_" + ir.resource() + "_" + ir.scope().replace('.', '_') + ".yaml";
        CerbosCompileGate.CompileOutcome outcome =
                compileGate.compile(canonical, Path.of(baseBundleDir), candidateFile);
        if (!outcome.success()) {
            return StudioGenerationResult.rejected(StudioGenerationResult.Stage.COMPILE,
                    List.of("cerbos compile rejected the candidate:\n" + outcome.output()));
        }

        return StudioGenerationResult.accepted(canonical, StudioGenerationResult.Stage.ACCEPTED);
    }
}
