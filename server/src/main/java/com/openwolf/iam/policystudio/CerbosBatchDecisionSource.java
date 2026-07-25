package com.openwolf.iam.policystudio;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.yaml.snakeyaml.DumperOptions;
import org.yaml.snakeyaml.Yaml;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.TimeUnit;
import java.util.stream.Stream;

/**
 * The REAL PDP source (Axiom Story C4): evaluates the fixture matrix against a bundle with the SAME
 * pinned Cerbos as the runtime PDP ({@code 0.53.0}), via an EPHEMERAL {@code docker run --rm} — no
 * container name, no port binding, policies mounted read-only. It therefore CANNOT collide with or
 * touch the running platform Cerbos PDP; it runs on a fresh temp dir every call and exits.
 *
 * <p><b>How a batch of CheckResources is realised deterministically:</b> the matrix is rendered as a
 * Cerbos test suite that asserts {@code EFFECT_ALLOW} for every cell, then {@code cerbos compile
 * -o json} evaluates the suite against {base bundle + candidate child}. Cerbos reports, per cell,
 * either a pass (the real decision was ALLOW) or a failure carrying {@code failure.actual} (the real
 * decision — EFFECT_ALLOW/EFFECT_DENY). That {@code actual} is the ground-truth PDP decision; the raw
 * JSON is retained as provenance. This is a real policy evaluation, not a paraphrase.
 */
@Component
public class CerbosBatchDecisionSource implements PdpDecisionSource {

    private static final Logger log = LoggerFactory.getLogger(CerbosBatchDecisionSource.class);
    private static final String SUITE = "ConsequenceProbe";
    private static final ObjectMapper JSON = new ObjectMapper();

    private final String cerbosImage;
    private final long timeoutSeconds;
    private final String cerbosVersion;
    private final String baseBundleDir;
    private final CanonicalPolicyWriter writer;

    public CerbosBatchDecisionSource(
            @Value("${iam.policy-studio.cerbos-image:ghcr.io/cerbos/cerbos:0.53.0}") String cerbosImage,
            @Value("${iam.policy-studio.compile-timeout-seconds:60}") long timeoutSeconds,
            @Value("${iam.policy-studio.cerbos-version:0.53.0}") String cerbosVersion,
            @Value("${iam.policy-studio.base-bundle-dir:/app/platform-policy/policies}") String baseBundleDir,
            CanonicalPolicyWriter writer) {
        this.cerbosImage = cerbosImage;
        this.timeoutSeconds = timeoutSeconds;
        this.cerbosVersion = cerbosVersion;
        this.baseBundleDir = baseBundleDir;
        this.writer = writer;
    }

    @Override
    public String sourceId() {
        return "cerbos:" + cerbosVersion;
    }

    @Override
    public boolean isAvailable() {
        return pinnedCerbosBinaryAvailable() || dockerDaemonAvailable();
    }

    @Override
    public PdpBatchResult evaluate(BundleSnapshot bundle, List<FixtureCell> cells) {
        Path work = null;
        try {
            work = Files.createTempDirectory("policystudio-c4-diff-");
            copyBundle(Path.of(baseBundleDir), work);
            String resourceKind = bundle.ceiling().resourceKind();
            String scope = bundle.policy() == null ? "" : nullToEmpty(bundle.policy().scope());
            if (bundle.policy() != null) {
                String childYaml = writer.write(bundle.policy());
                CerbosCompileGate.removeReplaceableTenantChild(work, childYaml);
                String candidateFile = "generated_" + resourceKind + "_"
                        + (scope.isEmpty() ? "root" : scope.replace('.', '_')) + ".yaml";
                Files.writeString(work.resolve(candidateFile), childYaml, StandardCharsets.UTF_8);
            }
            String suiteYaml = renderProbeSuite(cells, resourceKind, scope);
            Files.writeString(work.resolve("consequence_probe_test.yaml"), suiteYaml, StandardCharsets.UTF_8);

            String json = runCompile(work);
            return parse(json, bundle.bundleId(), cells);
        } catch (IOException | InterruptedException e) {
            if (e instanceof InterruptedException) {
                Thread.currentThread().interrupt();
            }
            throw new IllegalStateException("real-Cerbos consequence evaluation failed: " + e.getMessage(), e);
        } finally {
            if (work != null) {
                deleteRecursively(work);
            }
        }
    }

    // ── render the matrix as an assert-ALLOW-for-all Cerbos test suite ────────────────────────────

    private String renderProbeSuite(List<FixtureCell> cells, String resourceKind, String scope) {
        Map<String, Object> principals = new LinkedHashMap<>();
        Map<String, Object> resources = new LinkedHashMap<>();
        List<Object> tests = new ArrayList<>();

        for (int i = 0; i < cells.size(); i++) {
            FixtureCell cell = cells.get(i);
            String pid = "p" + i;
            String rid = "r" + i;

            Map<String, Object> principal = new LinkedHashMap<>();
            principal.put("id", pid);
            principal.put("roles", new ArrayList<>(new java.util.TreeSet<>(cell.principalRoles())));
            principal.put("attr", new LinkedHashMap<>(cell.effectivePrincipalAttrs()));
            principals.put(pid, principal);

            Map<String, Object> resource = new LinkedHashMap<>();
            resource.put("kind", resourceKind);
            resource.put("id", rid);
            resource.put("scope", scope);
            resource.put("attr", new LinkedHashMap<>(cell.effectiveResourceAttrs()));
            resources.put(rid, resource);

            Map<String, Object> input = new LinkedHashMap<>();
            input.put("principals", List.of(pid));
            input.put("resources", List.of(rid));
            input.put("actions", List.of(cell.action()));

            Map<String, Object> expectedActions = new LinkedHashMap<>();
            expectedActions.put(cell.action(), "EFFECT_ALLOW"); // assert-allow-for-all: pass ⇒ ALLOW, fail ⇒ actual
            Map<String, Object> expectedEntry = new LinkedHashMap<>();
            expectedEntry.put("principal", pid);
            expectedEntry.put("resource", rid);
            expectedEntry.put("actions", expectedActions);

            Map<String, Object> test = new LinkedHashMap<>();
            test.put("name", testName(i));
            test.put("input", input);
            test.put("expected", List.of(expectedEntry));
            tests.add(test);
        }

        Map<String, Object> doc = new LinkedHashMap<>();
        doc.put("name", SUITE);
        doc.put("description", "C4 assert-ALLOW-for-all consequence probe; PASS=ALLOW, FAIL=failure.actual");
        doc.put("principals", principals);
        doc.put("resources", resources);
        doc.put("tests", tests);

        DumperOptions opts = new DumperOptions();
        opts.setDefaultFlowStyle(DumperOptions.FlowStyle.BLOCK);
        opts.setIndent(2);
        opts.setLineBreak(DumperOptions.LineBreak.UNIX);
        return "---\n" + new Yaml(opts).dump(doc);
    }

    private static String testName(int i) {
        return "cell_" + i;
    }

    // ── run the ephemeral pinned Cerbos ────────────────────────────────────────────────────────────

    private String runCompile(Path policiesDir) throws IOException, InterruptedException {
        List<String> cmd = new ArrayList<>();
        if (pinnedCerbosBinaryAvailable()) {
            cmd.add("cerbos");
            cmd.add("compile");
            cmd.add("-o");
            cmd.add("json");
            cmd.add("--skip-batching");
            cmd.add("--test-filter=suite=" + SUITE);
            cmd.add(policiesDir.toAbsolutePath().toString());
        } else {
            cmd.add("docker");
            cmd.add("run");
            cmd.add("--rm");
            cmd.add("-v");
            cmd.add(policiesDir.toAbsolutePath() + ":/policies:ro");
            cmd.add("--entrypoint");
            cmd.add("/cerbos");
            cmd.add(cerbosImage);
            cmd.add("compile");
            cmd.add("-o");
            cmd.add("json");
            cmd.add("--skip-batching");
            cmd.add("--test-filter=suite=" + SUITE);
            cmd.add("/policies");
        }
        ProcessBuilder pb = new ProcessBuilder(cmd); // NOTE: do NOT merge stderr — JSON must be clean on stdout
        Process proc = pb.start();
        // Drain both pipes concurrently so neither can fill and deadlock the child. Crucially, apply
        // the timeout while the process is running — readAllBytes() before waitFor(timeout) would make
        // the advertised fail-closed deadline ineffective for a wedged Cerbos process.
        CompletableFuture<byte[]> stdoutBytes = CompletableFuture.supplyAsync(
                () -> readAllUnchecked(proc.getInputStream()));
        CompletableFuture<byte[]> stderrBytes = CompletableFuture.supplyAsync(
                () -> readAllUnchecked(proc.getErrorStream()));
        boolean finished = proc.waitFor(timeoutSeconds, TimeUnit.SECONDS);
        if (!finished) {
            proc.destroyForcibly();
            proc.waitFor(5, TimeUnit.SECONDS);
            throw new IOException("cerbos consequence evaluation timed out after " + timeoutSeconds + "s");
        }
        String stdout;
        String stderr;
        try {
            stdout = new String(stdoutBytes.join(), StandardCharsets.UTF_8);
            stderr = new String(stderrBytes.join(), StandardCharsets.UTF_8);
        } catch (CompletionException e) {
            throw new IOException("failed reading Cerbos consequence-evaluation output", e.getCause());
        }
        // Exit is non-zero whenever ANY asserted cell was actually DENY (expected ALLOW) — that is normal
        // for a diff. The authoritative signal is the JSON on stdout; only a MISSING suite is an error.
        if (stdout.isBlank()) {
            throw new IOException("cerbos produced no JSON output; stderr: " + stderr);
        }
        return stdout;
    }

    private static byte[] readAllUnchecked(InputStream stream) {
        try {
            return stream.readAllBytes();
        } catch (IOException e) {
            throw new CompletionException(e);
        }
    }

    private PdpBatchResult parse(String json, String bundleId, List<FixtureCell> cells) throws IOException {
        JsonNode root = JSON.readTree(json);
        JsonNode suites = root.path("suites");
        JsonNode probeSuite = null;
        for (JsonNode s : suites) {
            if (SUITE.equals(s.path("name").asText())) {
                probeSuite = s;
                break;
            }
        }
        if (probeSuite == null) {
            throw new IOException("cerbos output did not contain the '" + SUITE + "' suite: " + json);
        }
        Map<String, PdpDecision> byName = new LinkedHashMap<>();
        for (JsonNode tc : probeSuite.path("testCases")) {
            String tcName = tc.path("name").asText();
            JsonNode action = tc.path("principals").path(0)
                    .path("resources").path(0)
                    .path("actions").path(0);
            JsonNode details = action.path("details");
            String result = details.path("result").asText();
            Effect effect = "RESULT_FAILED".equals(result)
                    ? Effect.valueOf(details.path("failure").path("actual").asText().replace("EFFECT_", ""))
                    : Effect.ALLOW; // passed ⇒ the asserted EFFECT_ALLOW held
            String callId = SUITE + "/" + tcName;
            byName.put(tcName, new PdpDecision(tcName, effect, callId, action.toString()));
        }
        // Re-key from cerbos test-case names back to the fixture-cell labels, in matrix order.
        List<PdpDecision> decisions = new ArrayList<>(cells.size());
        for (int i = 0; i < cells.size(); i++) {
            PdpDecision d = byName.get(testName(i));
            if (d == null) {
                throw new IOException("cerbos did not evaluate cell " + i + " (" + cells.get(i).label() + ")");
            }
            decisions.add(new PdpDecision(cells.get(i).label(), d.effect(), d.callId(), d.rawResponse()));
        }
        return new PdpBatchResult(bundleId, sourceId(), decisions);
    }

    // ── plumbing (mirrors CerbosCompileGate: ephemeral, unnamed, no-port) ─────────────────────────

    private void copyBundle(Path from, Path to) throws IOException {
        if (from == null || !Files.isDirectory(from)) {
            throw new IOException("base bundle dir does not exist: " + from);
        }
        try (Stream<Path> walk = Files.walk(from)) {
            for (Path p : (Iterable<Path>) walk::iterator) {
                if (Files.isRegularFile(p)
                        && (p.toString().endsWith(".yaml") || p.toString().endsWith(".yml"))
                        // skip the base bundle's OWN test suites — we run only our probe suite
                        && !p.getFileName().toString().endsWith("_test.yaml")
                        && !p.getFileName().toString().endsWith("_test.yml")) {
                    Path target = to.resolve(from.relativize(p).toString().replace('/', '_'));
                    Files.copy(p, target, StandardCopyOption.REPLACE_EXISTING);
                }
            }
        }
    }

    private static String nullToEmpty(String s) {
        return s == null ? "" : s;
    }

    private static boolean dockerDaemonAvailable() {
        try {
            Process p = new ProcessBuilder("docker", "info", "--format", "{{.ServerVersion}}")
                    .redirectErrorStream(true).start();
            boolean done = p.waitFor(10, TimeUnit.SECONDS);
            if (!done) {
                p.destroyForcibly();
                return false;
            }
            return p.exitValue() == 0;
        } catch (IOException | InterruptedException e) {
            if (e instanceof InterruptedException) {
                Thread.currentThread().interrupt();
            }
            return false;
        }
    }

    private boolean pinnedCerbosBinaryAvailable() {
        try {
            Process p = new ProcessBuilder("cerbos", "--version").redirectErrorStream(true).start();
            boolean done = p.waitFor(10, TimeUnit.SECONDS);
            if (!done) {
                p.destroyForcibly();
                return false;
            }
            String version = new String(p.getInputStream().readAllBytes(), StandardCharsets.UTF_8).trim();
            return p.exitValue() == 0 && cerbosVersion.equals(version.lines().findFirst().orElse(""));
        } catch (IOException | InterruptedException e) {
            if (e instanceof InterruptedException) {
                Thread.currentThread().interrupt();
            }
            return false;
        }
    }

    private static void deleteRecursively(Path dir) {
        try (Stream<Path> walk = Files.walk(dir)) {
            walk.sorted((a, b) -> b.getNameCount() - a.getNameCount()).forEach(p -> {
                try {
                    Files.deleteIfExists(p);
                } catch (IOException ignored) {
                    // best-effort temp cleanup
                }
            });
        } catch (IOException ignored) {
            // best-effort temp cleanup
        }
    }
}
