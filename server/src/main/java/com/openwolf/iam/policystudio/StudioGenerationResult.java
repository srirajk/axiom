package com.openwolf.iam.policystudio;

import java.util.List;

/**
 * The outcome of one C2 authoring turn. On acceptance {@code canonicalYaml} is the IR-derived
 * canonical form that is safe to store; on rejection it is null and {@code violations} explains
 * why (parse failure, a deterministic-gate violation, or a compile failure). The model's raw text
 * is never returned for storage — only the canonical re-emission.
 *
 * @param accepted      whether the candidate passed parse + deterministic gate + compile
 * @param canonicalYaml the canonical, storable YAML (null when rejected)
 * @param violations    the reasons for rejection (empty when accepted)
 * @param stage         the stage that produced the outcome (for observability)
 */
public record StudioGenerationResult(
        boolean accepted,
        String canonicalYaml,
        List<String> violations,
        Stage stage) {

    public enum Stage {PARSE, VALIDATE, COMPILE, ACCEPTED, COMPILE_SKIPPED}

    public StudioGenerationResult {
        violations = List.copyOf(violations);
    }

    public static StudioGenerationResult rejected(Stage stage, List<String> violations) {
        return new StudioGenerationResult(false, null, violations, stage);
    }

    public static StudioGenerationResult accepted(String canonicalYaml, Stage stage) {
        return new StudioGenerationResult(true, canonicalYaml, List.of(), stage);
    }
}
