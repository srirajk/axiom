package com.openwolf.iam.policystudio;

import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.stream.Collectors;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * C3.2 — the MEASURED catch-rate over the hand-reviewed known-bad corpus, run through the REAL gate
 * with the pinned-Cerbos compile layer switched ON (H9).
 *
 * <p>It runs the full corpus (31 pairs) through {@link IndependentTestGenService#assess} with
 * {@code runCompile = true}, so the number reflects all three layers of the actual draft gate — the
 * independently-seeded oracle + mechanically-injected negative probes, the C2 deterministic validator,
 * AND the pinned-Cerbos compile (0.53.0) over the immutable base bundle. It asserts the aggregate
 * catch-rate is at least the honest measured floor, 100% for the cross-tenant AND wildcard classes, and
 * zero regression (every corpus item stays caught by its pinned layer). It emits a per-item pass/miss
 * table to {@code docs/implementation/evidence/studio/c3}.
 *
 * <p><b>What this number is and is NOT.</b> The oracle is a deterministic, HAND-SEEDED stub
 * ({@code C3TestGenFixtures.SeededIntentOracle}) authored in the same commit as the paired bad YAML,
 * and the corpus is therefore a CLOSED LOOP. The rate is a <b>floor over KNOWN bad pairs</b> — it is
 * NOT a guarantee over unseen policy. Two things push past the closed loop: (1) the compile layer here
 * is the real Cerbos, not a Java re-implementation; (2) {@link #heldOutUnseenPolicyProbe()} throws bad
 * policies the corpus never contained at the same trained gate, for a sliver of unseen-policy signal.
 *
 * <p><b>Docker is required</b> (the compile layer runs an ephemeral {@code docker run --rm}). Locally,
 * a box without Docker assume-skips so the unit suite still runs; in CI, {@code CONDUIT_DOCKER_REQUIRED=true}
 * turns that skip into a HARD FAILURE (H7) — a silently-skipped compile must not pass the gate green.
 */
class KnownBadCorpusCatchRateTest {

    // Honest, measured floor. With compile ON the validator + oracle already catch every corpus item,
    // so the compile layer adds no NET catch here (it is belt-and-braces and independently confirms the
    // structural rejects); the aggregate stays 100%. Kept at 0.90 so a future adversarial addition that
    // slips one item still turns the bar red rather than silently lowering an inflated 100%.
    private static final double AGGREGATE_THRESHOLD = 0.90;

    // Pinned to 0.53.0 — the exact version the runtime Cerbos PDP + the provisioning/policy gate run.
    // An unpinned :latest could silently drift compile semantics. Overridable via CERBOS_IMAGE.
    private static final String CERBOS_IMAGE =
            System.getenv().getOrDefault("CERBOS_IMAGE", "ghcr.io/cerbos/cerbos:0.53.0");

    @BeforeEach
    void requireDocker() {
        boolean docker = dockerAvailable();
        boolean requiredInCi = Boolean.parseBoolean(
                System.getenv().getOrDefault("CONDUIT_DOCKER_REQUIRED", "false"));
        if (requiredInCi) {
            assertThat(docker)
                    .as("CONDUIT_DOCKER_REQUIRED=true (CI) but Docker is unavailable — the C3 catch-rate "
                            + "must RUN with the real compile ON, not skip green")
                    .isTrue();
        } else {
            Assumptions.assumeTrue(docker,
                    "Docker not available — skipping the C3 catch-rate (it now requires the real compile)");
        }
    }

    private IndependentTestGenService newService() {
        return new IndependentTestGenService(
                C3Corpus.oracle(),
                new NegativeProbeInjector(),
                new PolicyExpectationEvaluator(new ConditionEvaluator()),
                new GeneratedPolicyValidator(),
                new CanonicalPolicyWriter(),
                new CerbosCompileGate(CERBOS_IMAGE, 90),
                // The immutable base bundle the candidate is compiled against — the classpath copy, so the
                // compile has real base policies to assemble the candidate with (NOT a bare relative path).
                PolicyStudioFixtures.baseBundleDir().toString());
    }

    private record Row(
            String id, String category, CatchLayer expected, CatchLayer actual,
            boolean caught, boolean moatCritical, boolean compileRan, boolean compileCaught,
            Set<ProbeKind> failingProbes, int validatorViolations, String note) {}

    @Test
    void overGrantYamlCaughtBeforeApproval() {
        IndependentTestGenService svc = newService();
        PolicyYamlParser parser = new PolicyYamlParser();
        ProbeAttributes probeAttrs = C3TestGenFixtures.probeAttributes();

        List<C3Corpus.Item> corpus = C3Corpus.items();
        assertThat(corpus).as("the known-bad corpus must have at least 30 items").hasSizeGreaterThanOrEqualTo(30);

        List<Row> rows = new ArrayList<>();
        String sampleOracleYaml = null;
        for (C3Corpus.Item item : corpus) {
            PolicyIR ir = parser.parse(item.badYaml());
            IndependentTestGenService.TestGenReport r =
                    svc.assess(item.request(), ir, probeAttrs, /* runCompile */ true);
            Set<ProbeKind> failing = r.oracleFailures().stream()
                    .map(Expectation::kind).collect(Collectors.toCollection(java.util.LinkedHashSet::new));
            rows.add(new Row(item.id(), item.category(), item.expectedLayer(), r.primaryLayer(),
                    r.caught(), r.moatCritical(), r.invariantSuiteRun(), r.compileCaught(),
                    failing, r.validatorViolations().size(), item.note()));
            if (sampleOracleYaml == null && item.expectedLayer() == CatchLayer.ORACLE) {
                sampleOracleYaml = "# Rendered from item " + item.id() + " — intent: "
                        + item.request().intent() + "\n" + r.oracleTestYaml();
            }
        }

        long caught = rows.stream().filter(Row::caught).count();
        double rate = (double) caught / rows.size();
        List<Row> misses = rows.stream().filter(row -> !row.caught()).toList();

        // Per-category rates.
        Map<String, long[]> perCat = new TreeMap<>(); // cat -> [caught, total]
        for (Row row : rows) {
            long[] cc = perCat.computeIfAbsent(row.category(), k -> new long[2]);
            if (row.caught()) {
                cc[0]++;
            }
            cc[1]++;
        }

        writeEvidence(rows, rate, perCat, misses, sampleOracleYaml);

        // ── Assertions ────────────────────────────────────────────────────────────────────────────
        // The real compile layer actually RAN for every item (this is the whole point of H9 — the
        // number is not produced with the Cerbos layer switched off).
        for (Row row : rows) {
            assertThat(row.compileRan())
                    .as("item %s: the pinned-Cerbos compile layer must have RUN (compile ON)", row.id())
                    .isTrue();
        }

        // Aggregate ≥ the honest floor.
        assertThat(rate)
                .as("aggregate catch-rate over %d known-bad pairs (misses: %s)", rows.size(),
                        misses.stream().map(Row::id).toList())
                .isGreaterThanOrEqualTo(AGGREGATE_THRESHOLD);

        // 100% for the cross-tenant AND wildcard classes.
        assertCategory100(perCat, C3TestGenFixtures.CAT_CROSS_TENANT);
        assertCategory100(perCat, C3TestGenFixtures.CAT_WILDCARD);

        // Zero regression: every item stays caught, and by the layer it is pinned to.
        for (Row row : rows) {
            assertThat(row.caught())
                    .as("regression: corpus item %s (%s) is no longer caught", row.id(), row.category())
                    .isTrue();
            assertThat(row.actual())
                    .as("corpus item %s changed catch layer (expected %s)", row.id(), row.expected())
                    .isEqualTo(row.expected());
            if (row.expected() == CatchLayer.ORACLE) {
                assertThat(row.moatCritical())
                        .as("item %s must be moat-critical (validator-clean, oracle-caught)", row.id())
                        .isTrue();
            }
        }

        // The moat must not be vacuous: a substantial set is caught ONLY by the independent oracle.
        long moat = rows.stream().filter(Row::moatCritical).count();
        assertThat(moat)
                .as("moat-critical items (validator accepted, oracle caught) — the co-generated blind spot")
                .isGreaterThanOrEqualTo(10);
    }

    /**
     * A small HELD-OUT probe: bad POLICIES the corpus never contained, paired with EXISTING intents, run
     * through the SAME trained gate with the real compile ON. The oracle/validator/probes are exactly
     * the ones trained on the 31-item corpus; only the candidate YAML here is unseen. This is the sliver
     * of unseen-policy signal the closed-loop corpus cannot give: if the gate catches policies it was
     * never shown, that is evidence it generalizes rather than memorizes. Reported separately in
     * {@code held-out-probe.md}, clearly labeled as the held-out set (NOT part of the 31).
     */
    @Test
    void heldOutUnseenPolicyProbe() {
        IndependentTestGenService svc = newService();
        PolicyYamlParser parser = new PolicyYamlParser();
        ProbeAttributes probeAttrs = C3TestGenFixtures.probeAttributes();

        List<HeldOut> held = heldOutItems();
        List<Row> rows = new ArrayList<>();
        for (HeldOut h : held) {
            PolicyIR ir = parser.parse(h.badYaml());
            IndependentTestGenService.TestGenReport r =
                    svc.assess(h.request(), ir, probeAttrs, /* runCompile */ true);
            Set<ProbeKind> failing = r.oracleFailures().stream()
                    .map(Expectation::kind).collect(Collectors.toCollection(java.util.LinkedHashSet::new));
            rows.add(new Row(h.id(), h.category(), h.expectHint(), r.primaryLayer(),
                    r.caught(), r.moatCritical(), r.invariantSuiteRun(), r.compileCaught(),
                    failing, r.validatorViolations().size(), h.note()));
        }

        long caught = rows.stream().filter(Row::caught).count();
        double rate = (double) caught / rows.size();
        long moat = rows.stream().filter(Row::moatCritical).count();
        writeHeldOutEvidence(rows, rate);

        // Every held-out bad policy must be caught by the gate it never saw.
        for (Row row : rows) {
            assertThat(row.compileRan())
                    .as("held-out %s: the pinned-Cerbos compile layer must have RUN", row.id())
                    .isTrue();
            assertThat(row.caught())
                    .as("held-out (unseen) bad policy %s (%s) slipped the trained gate: %s",
                            row.id(), row.category(), row.note())
                    .isTrue();
        }
        assertThat(rate).as("held-out unseen catch-rate (%d/%d)", caught, rows.size())
                .isEqualTo(1.0);
        // At least one unseen policy is caught ONLY by the independent oracle — the moat generalizes
        // past the memorized corpus, not just the structural validator.
        assertThat(moat)
                .as("at least one held-out policy must be moat-critical (oracle-caught, validator-clean)")
                .isGreaterThanOrEqualTo(1);
    }

    // ── held-out set (unseen bad policies, existing intents so the seeded oracle resolves) ──────────

    private record HeldOut(String id, String category, PolicyAuthoringRequest request,
                           String badYaml, CatchLayer expectHint, String note) {}

    private List<HeldOut> heldOutItems() {
        return List.of(
                // Unseen wildcard: chat_user wildcard smuggled among finite actions (corpus never had
                // this exact shape for chat_user). Structural → validator.
                new HeldOut("HO-01", C3TestGenFixtures.CAT_WILDCARD,
                        C3TestGenFixtures.acmeRequest("WC-05: chat_user actions must be enumerated."),
                        """
                        apiVersion: api.cerbos.dev/v1
                        resourcePolicy:
                          version: "default"
                          resource: agent
                          scope: "acme"
                          scopePermissions: SCOPE_PERMISSIONS_REQUIRE_PARENTAL_CONSENT_FOR_ALLOWS
                          rules:
                            - actions: ["invoke", "invoke_membership", "register", "deregister"]
                              effect: EFFECT_ALLOW
                              roles: ["platform_admin"]
                            - actions: ["invoke", "invoke_membership", "register", "deregister"]
                              effect: EFFECT_ALLOW
                              roles: ["domain_admin"]
                            - actions: ["invoke", "invoke_membership", "*"]
                              effect: EFFECT_ALLOW
                              roles: ["chat_user"]
                            - actions: ["invoke", "invoke_membership"]
                              effect: EFFECT_ALLOW
                              roles: ["relationship_manager"]
                        """,
                        CatchLayer.VALIDATOR,
                        "Unseen: chat_user gets actions:['invoke','invoke_membership','*'] — a wildcard hidden in a finite rule."),

                // Unseen cross-tenant: target a THIRD sibling tenant ('delta') the corpus never used.
                new HeldOut("HO-02", C3TestGenFixtures.CAT_CROSS_TENANT,
                        C3TestGenFixtures.acmeRequest("CT-03: acme author may only touch tenant acme."),
                        C3TestGenFixtures.compliant("delta"),
                        CatchLayer.VALIDATOR,
                        "Unseen: targets sibling tenant 'delta' (corpus used 'beta') — out-of-subtree escape."),

                // Unseen fall-through: drop platform_admin REGISTER specifically (corpus dropped other tuples).
                new HeldOut("HO-03", C3TestGenFixtures.CAT_INCOMPLETE_FALLTHROUGH,
                        C3TestGenFixtures.acmeRequest("FT-01: acme child must have an explicit opinion on every base tuple."),
                        """
                        apiVersion: api.cerbos.dev/v1
                        resourcePolicy:
                          version: "default"
                          resource: agent
                          scope: "acme"
                          scopePermissions: SCOPE_PERMISSIONS_REQUIRE_PARENTAL_CONSENT_FOR_ALLOWS
                          rules:
                            - actions: ["invoke", "invoke_membership", "deregister"]
                              effect: EFFECT_ALLOW
                              roles: ["platform_admin"]
                            - actions: ["invoke", "invoke_membership", "register", "deregister"]
                              effect: EFFECT_ALLOW
                              roles: ["domain_admin"]
                            - actions: ["invoke", "invoke_membership"]
                              effect: EFFECT_ALLOW
                              roles: ["chat_user", "relationship_manager"]
                        """,
                        CatchLayer.VALIDATOR,
                        "Unseen: drops (register, platform_admin) — that base tuple falls through to the parent ALLOW."),

                // Unseen MOAT: validator-clean body that grants chat_user invoke_membership via a SPLIT
                // rule (distinct shape from the corpus's combined chat_user+rm rule). Only the oracle,
                // built from the intent's explicit DENY, catches it.
                new HeldOut("HO-04", C3TestGenFixtures.CAT_WRONG_ROLE_SEGMENT,
                        C3TestGenFixtures.acmeRequest("WR-01: acme chat_user may invoke internal agents but must NOT probe membership."),
                        """
                        apiVersion: api.cerbos.dev/v1
                        resourcePolicy:
                          version: "default"
                          resource: agent
                          scope: "acme"
                          scopePermissions: SCOPE_PERMISSIONS_REQUIRE_PARENTAL_CONSENT_FOR_ALLOWS
                          rules:
                            - actions: ["invoke", "invoke_membership", "register", "deregister"]
                              effect: EFFECT_ALLOW
                              roles: ["platform_admin"]
                            - actions: ["invoke", "invoke_membership", "register", "deregister"]
                              effect: EFFECT_ALLOW
                              roles: ["domain_admin"]
                            - actions: ["invoke", "invoke_membership"]
                              effect: EFFECT_ALLOW
                              roles: ["chat_user"]
                            - actions: ["invoke", "invoke_membership"]
                              effect: EFFECT_ALLOW
                              roles: ["relationship_manager"]
                        """,
                        CatchLayer.ORACLE,
                        "Unseen moat: validator-clean, but leaves chat_user invoke_membership ALLOW — only the intent-built oracle denies it."),

                // Unseen wildcard #2: platform_admin wildcard smuggled among finite actions.
                new HeldOut("HO-05", C3TestGenFixtures.CAT_WILDCARD,
                        C3TestGenFixtures.acmeRequest("WC-02: platform_admin actions must be enumerated."),
                        """
                        apiVersion: api.cerbos.dev/v1
                        resourcePolicy:
                          version: "default"
                          resource: agent
                          scope: "acme"
                          scopePermissions: SCOPE_PERMISSIONS_REQUIRE_PARENTAL_CONSENT_FOR_ALLOWS
                          rules:
                            - actions: ["invoke", "register", "*"]
                              effect: EFFECT_ALLOW
                              roles: ["platform_admin"]
                            - actions: ["invoke", "invoke_membership", "register", "deregister"]
                              effect: EFFECT_ALLOW
                              roles: ["domain_admin"]
                            - actions: ["invoke", "invoke_membership"]
                              effect: EFFECT_ALLOW
                              roles: ["chat_user", "relationship_manager"]
                        """,
                        CatchLayer.VALIDATOR,
                        "Unseen: platform_admin gets actions:['invoke','register','*'] — a wildcard hidden in a finite rule.")
        );
    }

    private void assertCategory100(Map<String, long[]> perCat, String category) {
        long[] cc = perCat.get(category);
        assertThat(cc).as("category '%s' must be present in the corpus", category).isNotNull();
        assertThat(cc[0])
                .as("category '%s' must be 100%% caught (%d/%d)", category, cc[0], cc[1])
                .isEqualTo(cc[1]);
    }

    // ── evidence emission ──────────────────────────────────────────────────────────────────────

    private void writeEvidence(List<Row> rows, double rate, Map<String, long[]> perCat, List<Row> misses,
                               String sampleOracleYaml) {
        StringBuilder md = new StringBuilder();
        md.append("# C3.2 — Known-bad corpus catch-rate (MEASURED, real Cerbos compile ON)\n\n");
        md.append("> Auto-generated by `KnownBadCorpusCatchRateTest`. **What this number is:** a FLOOR over\n")
          .append("> the hand-reviewed KNOWN-bad corpus — NOT a guarantee over unseen policy. The oracle is a\n")
          .append("> hand-seeded deterministic stub authored in the same commit as the bad YAML, so the corpus\n")
          .append("> is a closed loop. Two things push past it: the compile layer below is the REAL pinned\n")
          .append("> Cerbos (not a Java re-implementation), and `held-out-probe.md` throws unseen policies at\n")
          .append("> the same trained gate. Add adversarial pairs over time; the gate must keep clearing the bars.\n\n");
        md.append("**Harness (three layers, all live):** deterministic seeded oracle (NO real LLM) + mechanical\n")
          .append("negative probes + C2 deterministic validator + **pinned-Cerbos `0.53.0` compile** over the\n")
          .append("immutable base bundle. Docker required (H7 hard-require in CI).\n\n");
        md.append(String.format("## Headline%n%n"));
        long caught = rows.stream().filter(Row::caught).count();
        long moat = rows.stream().filter(Row::moatCritical).count();
        long compileRan = rows.stream().filter(Row::compileRan).count();
        long compileCaught = rows.stream().filter(Row::compileCaught).count();
        md.append(String.format("- **Aggregate catch-rate: %.1f%% (%d/%d)** — with the real compile ON%n",
                rate * 100, caught, rows.size()));
        md.append(String.format("- **Compile layer actually ran: %d/%d items** (independently rejected %d)%n",
                compileRan, rows.size(), compileCaught));
        md.append(String.format("- **Moat-critical (validator-clean, caught ONLY by the independent oracle): %d**%n", moat));
        md.append(String.format("- **Misses: %d** %s%n", misses.size(),
                misses.isEmpty() ? "" : misses.stream().map(Row::id).collect(Collectors.joining(", ", "(", ")"))));
        md.append("\n> The compile layer adds no NET catch here because the validator + oracle already catch\n")
          .append("> every item; it is belt-and-braces and independently confirms the structural rejects. Its\n")
          .append("> value is that the measured gate is the REAL one, and a future regression that only Cerbos\n")
          .append("> would catch is now covered.\n");
        md.append("\n## Per-class rate\n\n| Class | Caught | Total | Rate |\n|---|---|---|---|\n");
        for (Map.Entry<String, long[]> e : perCat.entrySet()) {
            long[] cc = e.getValue();
            md.append(String.format("| %s | %d | %d | %.0f%% |%n", e.getKey(), cc[0], cc[1],
                    100.0 * cc[0] / cc[1]));
        }
        md.append("\n## Per-item pass/miss table\n\n");
        md.append("| ID | Class | Expected layer | Actual layer | Caught | Moat-critical | Compile ran | Failing probes | Note |\n");
        md.append("|---|---|---|---|---|---|---|---|---|\n");
        for (Row row : rows) {
            md.append(String.format("| %s | %s | %s | %s | %s | %s | %s | %s | %s |%n",
                    row.id(), row.category(), row.expected(), row.actual(),
                    row.caught() ? "yes" : "MISS", row.moatCritical() ? "yes" : "",
                    row.compileRan() ? "yes" : "no",
                    row.failingProbes().isEmpty() ? "—" : row.failingProbes().toString(),
                    row.note()));
        }
        if (!misses.isEmpty()) {
            md.append("\n## Published misses\n\n");
            for (Row m : misses) {
                md.append(String.format("- **%s** (%s): %s%n", m.id(), m.category(), m.note()));
            }
        }
        String content = md.toString();

        Path dir = resolveEvidenceDir();
        try {
            Files.createDirectories(dir);
            Files.writeString(dir.resolve("catch-rate-table.md"), content, StandardCharsets.UTF_8);
            if (sampleOracleYaml != null) {
                Files.writeString(dir.resolve("sample-oracle-test.yaml"), sampleOracleYaml, StandardCharsets.UTF_8);
            }
        } catch (IOException ignored) {
            // Evidence emission is best-effort; the assertions above are the source of truth.
        }
        // Always echo the headline so it is captured in the build log.
        System.out.printf("[C3.2] catch-rate=%.1f%% caught=%d/%d moat-critical=%d compileRan=%d/%d misses=%d -> %s%n",
                rate * 100, caught, rows.size(), moat, compileRan, rows.size(), misses.size(),
                dir.resolve("catch-rate-table.md"));
    }

    private void writeHeldOutEvidence(List<Row> rows, double rate) {
        StringBuilder md = new StringBuilder();
        md.append("# C3.2 — HELD-OUT unseen-policy probe (labeled: NOT part of the 31-item corpus)\n\n");
        md.append("> Auto-generated by `KnownBadCorpusCatchRateTest.heldOutUnseenPolicyProbe`. These are bad\n")
          .append("> POLICIES the corpus never contained, paired with EXISTING intents, run through the SAME\n")
          .append("> trained gate (seeded oracle + probes + validator + real pinned-Cerbos `0.53.0` compile).\n")
          .append("> Only the candidate YAML is unseen — the gate is exactly the one measured over the 31.\n")
          .append("> This is a SLIVER of unseen-policy signal, not a completeness claim.\n\n");
        long caught = rows.stream().filter(Row::caught).count();
        long moat = rows.stream().filter(Row::moatCritical).count();
        md.append(String.format("## Headline%n%n"));
        md.append(String.format("- **Held-out catch-rate: %.1f%% (%d/%d)**%n", rate * 100, caught, rows.size()));
        md.append(String.format("- **Held-out moat-critical (oracle generalized to unseen policy): %d**%n", moat));
        md.append("\n## Held-out items\n\n");
        md.append("| ID | Class | Caught by | Caught | Moat-critical | Compile ran | Note |\n");
        md.append("|---|---|---|---|---|---|---|\n");
        for (Row row : rows) {
            md.append(String.format("| %s | %s | %s | %s | %s | %s | %s |%n",
                    row.id(), row.category(), row.actual(),
                    row.caught() ? "yes" : "MISS", row.moatCritical() ? "yes" : "",
                    row.compileRan() ? "yes" : "no", row.note()));
        }
        Path dir = resolveEvidenceDir();
        try {
            Files.createDirectories(dir);
            Files.writeString(dir.resolve("held-out-probe.md"), md.toString(), StandardCharsets.UTF_8);
        } catch (IOException ignored) {
            // best-effort
        }
        System.out.printf("[C3.2 held-out] catch-rate=%.1f%% caught=%d/%d moat=%d -> %s%n",
                rate * 100, caught, rows.size(), moat, dir.resolve("held-out-probe.md"));
    }

    /** Walk up from the working dir to the repo root; fall back to the module target dir. */
    private Path resolveEvidenceDir() {
        File cur = new File("").getAbsoluteFile();
        for (int i = 0; i < 6 && cur != null; i++) {
            File candidate = new File(cur, "docs/implementation/evidence/studio/c3");
            if (new File(cur, "docs/implementation").isDirectory()) {
                return candidate.toPath();
            }
            cur = cur.getParentFile();
        }
        return new File("target/c3-evidence").toPath();
    }

    private static boolean dockerAvailable() {
        try {
            Process p = new ProcessBuilder("docker", "--version").redirectErrorStream(true).start();
            return p.waitFor() == 0;
        } catch (Exception e) {
            return false;
        }
    }
}
