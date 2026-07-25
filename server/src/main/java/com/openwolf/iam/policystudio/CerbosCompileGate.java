package com.openwolf.iam.policystudio;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.stream.Stream;

import com.openwolf.iam.policystudio.lifecycle.BundleFile;
import com.openwolf.iam.policystudio.lifecycle.ResourcePolicyIdentity;

/**
 * Compiles a generated candidate together with the EXACT immutable base bundle it targets, using
 * the SAME pinned Cerbos as the runtime PDP (Axiom Story C2 — "the compile gate is a control").
 * A candidate that omits a base tuple, adds a wildcard grant, changes a base policy, or collides
 * with another policy identity fails here (Cerbos surfaces duplicate scope+resource, unknown
 * imports, and schema errors) and is never stored.
 *
 * <p>Runtime safety: runs an EPHEMERAL {@code docker run --rm} with no container name and no port
 * binding, so it can never collide with or touch the running platform Cerbos PDP. The
 * policies are mounted read-only. If neither a local {@code cerbos} binary nor Docker with the
 * pinned image is available, {@link #isAvailable()} returns false so callers/tests can degrade
 * (the deterministic parser/validator gate does not need Cerbos; only this final compile does).
 */
@Component
public class CerbosCompileGate {

    private static final Logger log = LoggerFactory.getLogger(CerbosCompileGate.class);

    private final String cerbosImage;
    private final long timeoutSeconds;

    public CerbosCompileGate(
            @Value("${iam.policy-studio.cerbos-image:ghcr.io/cerbos/cerbos:0.53.0}") String cerbosImage,
            @Value("${iam.policy-studio.compile-timeout-seconds:60}") long timeoutSeconds) {
        this.cerbosImage = cerbosImage;
        this.timeoutSeconds = timeoutSeconds;
    }

    public record CompileOutcome(boolean success, String output) {}

    /** True iff a local pinned {@code cerbos} binary OR Docker (assumed to hold the pinned image)
     *  is usable. Tests use this to {@code assumeTrue} rather than fail on a Cerbos-less box. */
    public boolean isAvailable() {
        return commandExists("cerbos") || commandExists("docker");
    }

    /**
     * Assemble {baseBundleDir + candidate} into an isolated temp dir and compile it.
     *
     * @param candidateYaml    the canonical candidate YAML (never the model's raw text)
     * @param baseBundleDir    a directory holding the immutable base policies + derived-role modules
     * @param candidateFileName the file name to write the candidate under (drives identity collision)
     */
    public CompileOutcome compile(String candidateYaml, Path baseBundleDir, String candidateFileName) {
        Path work = null;
        try {
            work = Files.createTempDirectory("policystudio-compile-");
            copyBundle(baseBundleDir, work);
            removeReplaceableTenantChild(work, candidateYaml);
            Files.writeString(work.resolve(candidateFileName), candidateYaml, StandardCharsets.UTF_8);
            return runCompile(work);
        } catch (IOException | InterruptedException e) {
            if (e instanceof InterruptedException) {
                Thread.currentThread().interrupt();
            }
            return new CompileOutcome(false, "compile gate error: " + e.getMessage());
        } finally {
            if (work != null) {
                deleteRecursively(work);
            }
        }
    }

    /**
     * Compile a SELF-CONTAINED candidate bundle from ONLY its own captured files — no external base
     * directory is read (S3, Bug B). The bundle must already carry its whole policy universe (base ceiling
     * + scope-chain + imported derived-roles / variables + tenant child); this stages exactly those files
     * into an isolated temp dir and compiles them. Used by the promotion probe so a candidate's compile
     * depends only on its content-addressed contents, never on a mutable external base dir.
     */
    public CompileOutcome compile(List<BundleFile> candidateFiles) {
        Path work = null;
        try {
            work = Files.createTempDirectory("policystudio-compile-selfcontained-");
            for (BundleFile file : candidateFiles) {
                Files.writeString(work.resolve(stagedFileName(file.path())), file.yaml(), StandardCharsets.UTF_8);
            }
            return runCompile(work);
        } catch (IOException | InterruptedException e) {
            if (e instanceof InterruptedException) {
                Thread.currentThread().interrupt();
            }
            return new CompileOutcome(false, "compile gate error: " + e.getMessage());
        } finally {
            if (work != null) {
                deleteRecursively(work);
            }
        }
    }

    /**
     * Assemble {baseBundleDir + full candidate bundle} into an isolated temp dir and compile it as one
     * policy universe. This is required for scoped resource policies: a tenant child at
     * {@code scope: default} must compile alongside its same-version root parent.
     */
    public CompileOutcome compile(List<BundleFile> candidateFiles, Path baseBundleDir) {
        Path work = null;
        try {
            work = Files.createTempDirectory("policystudio-compile-");
            copyBundle(baseBundleDir, work);
            for (BundleFile file : candidateFiles) {
                Files.writeString(work.resolve(stagedFileName(file.path())), file.yaml(), StandardCharsets.UTF_8);
            }
            return runCompile(work);
        } catch (IOException | InterruptedException e) {
            if (e instanceof InterruptedException) {
                Thread.currentThread().interrupt();
            }
            return new CompileOutcome(false, "compile gate error: " + e.getMessage());
        } finally {
            if (work != null) {
                deleteRecursively(work);
            }
        }
    }

    private CompileOutcome runCompile(Path policiesDir) throws IOException, InterruptedException {
        List<String> cmd = new ArrayList<>();
        if (commandExists("cerbos")) {
            cmd.add("cerbos");
            cmd.add("compile");
            cmd.add(policiesDir.toAbsolutePath().toString());
        } else {
            // Ephemeral, unnamed, no-port container — cannot touch the running PDP.
            cmd.add("docker");
            cmd.add("run");
            cmd.add("--rm");
            cmd.add("-v");
            cmd.add(policiesDir.toAbsolutePath() + ":/policies:ro");
            cmd.add("--entrypoint");
            cmd.add("/cerbos");
            cmd.add(cerbosImage);
            cmd.add("compile");
            cmd.add("/policies");
        }

        ProcessBuilder pb = new ProcessBuilder(cmd).redirectErrorStream(true);
        Process proc = pb.start();
        String output = new String(proc.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
        boolean finished = proc.waitFor(timeoutSeconds, TimeUnit.SECONDS);
        if (!finished) {
            proc.destroyForcibly();
            return new CompileOutcome(false, "cerbos compile timed out after " + timeoutSeconds + "s");
        }
        int code = proc.exitValue();
        if (code != 0) {
            log.debug("cerbos compile failed ({}):\n{}", code, output);
        }
        return new CompileOutcome(code == 0, output);
    }

    private void copyBundle(Path from, Path to) throws IOException {
        if (from == null || !Files.isDirectory(from)) {
            throw new IOException("base bundle dir does not exist: " + from);
        }
        try (Stream<Path> walk = Files.walk(from)) {
            for (Path p : (Iterable<Path>) walk::iterator) {
                if (Files.isRegularFile(p)
                        && isDeployablePolicyYaml(from, p)) {
                    Path target = to.resolve(from.relativize(p).toString().replace('/', '_'));
                    Files.copy(p, target, StandardCopyOption.REPLACE_EXISTING);
                }
            }
        }
    }

    /** Cerbos test suites are verification inputs, not deployable policy/module definitions. */
    private static boolean isDeployablePolicyYaml(Path root, Path file) {
        String name = file.getFileName().toString();
        if (!(name.endsWith(".yaml") || name.endsWith(".yml"))
                || name.endsWith("_test.yaml") || name.endsWith("_test.yml")) {
            return false;
        }
        String relative = root.relativize(file).toString().replace('\\', '/');
        return !relative.startsWith("tests/") && !relative.contains("/tests/");
    }

    /**
     * A tenant draft replaces that tenant's existing child for the same resource kind. The immutable root
     * ceiling remains in the compile universe, but retaining the old child beside its replacement would
     * create a false duplicate-identity failure (notably for the seeded {@code default} tenant).
     */
    static void removeReplaceableTenantChild(Path stagedDir, String candidateYaml) throws IOException {
        ResourcePolicyIdentity candidate = ResourcePolicyIdentity.fromYaml(candidateYaml).orElse(null);
        if (candidate == null || candidate.scope().isBlank()) {
            return; // root policies are immutable and must never be removed/replaced here
        }
        try (Stream<Path> files = Files.list(stagedDir)) {
            for (Path file : files.filter(Files::isRegularFile).toList()) {
                if (ResourcePolicyIdentity.fromYaml(Files.readString(file))
                        .map(candidate::equals).orElse(false)) {
                    Files.delete(file);
                }
            }
        }
    }

    private static String stagedFileName(String path) {
        String fileName = "staged_" + path.replace('/', '_').replace('@', '_');
        if (!fileName.endsWith(".yaml") && !fileName.endsWith(".yml")) {
            fileName = fileName + ".yaml";
        }
        return fileName;
    }

    private static boolean commandExists(String cmd) {
        try {
            Process p = new ProcessBuilder(cmd, "--version").redirectErrorStream(true).start();
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
