package com.openwolf.iam.policystudio.lifecycle;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.security.MessageDigest;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.StandardOpenOption;
import java.nio.file.StandardCopyOption;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Objects;

/**
 * S1a — the missing runtime-load wire (lifecycle-spine hardening). After a candidate bundle compiles and
 * the activation CAS flips the tenant's active pointer, this loader <b>materialises the promoted bundle's
 * rendered policies — each stamped {@code policyVersion = <bundleId>} — into the store the serving Cerbos
 * PDP reads</b>, so the promotion the control plane performed actually changes runtime enforcement instead
 * of only flipping a pointer the PDP never sees.
 *
 * <p><b>Two backends, one write.</b> Production writes to an <b>S3-family bucket</b> ({@link
 * S3RuntimePolicySink}) that Cerbos serves with its {@code blob} storage driver and <b>polls</b> on
 * {@code updatePollInterval} — the reliable path, immune to the macOS-VirtioFS host→container inotify event
 * loss that the disk + {@code watchForChanges} path suffered. When no bucket is configured the loader falls
 * back to the legacy <b>watched-directory</b> write (disk driver) — retained so the disk-based enforcement
 * ITs keep exercising a real reload, and as a one-commit revert path for the live switch. A configured
 * bucket wins; only if it is unset does the directory apply; unset both ⇒ a logged no-op.
 *
 * <p><b>Additive, never destructive.</b> Every file is namespaced by the content-addressed {@code bundleId}
 * and every policy inside carries {@code version: <bundleId>} (the {@link StagingCandidateProbe} invariant).
 * A resource policy is keyed in Cerbos by {@code (kind, version, scope)}, so a promoted bundle's
 * {@code version=<bundleId>} policies coexist with the base {@code version=default} policies — the default
 * tenant keeps evaluating {@code default} unchanged, and a promoted tenant (whose
 * {@code activePolicyVersion} the serving layer now sends) evaluates its own bundle.
 *
 * <p><b>Topology.</b> The watched directory is a writable volume shared by iam-service (writes here) and the
 * Cerbos container (reads, under its watched {@code /conf/policies}). The path is configured via
 * {@code iam.policy-studio.runtime-policies-dir} (env {@code IAM_POLICY_STUDIO_RUNTIME_POLICIES_DIR}) — never
 * a hardcoded path. When it is unset (a checkout with no runtime volume, e.g. most unit tests) the load is a
 * logged no-op so the deterministic promotion machinery still runs; a configured-but-unwritable dir
 * fail-closes the promotion (the CAS is rolled back by the surrounding transaction).
 */
@Component
public class PromotedBundleLoader {

    private static final Logger log = LoggerFactory.getLogger(PromotedBundleLoader.class);

    private final String runtimePoliciesDir;
    private final long tierSettleMs;
    private final int emitPasses;
    private final CerbosRuntimeActivationProbe activationProbe;

    /** Production blob backend — non-null iff a runtime bucket is configured; then it wins over the dir. */
    private final S3RuntimePolicySink s3Sink;

    /** Test/convenience constructor: default settle + re-emit passes, disk-only, no Spring binding. */
    public PromotedBundleLoader(String runtimePoliciesDir) {
        this(runtimePoliciesDir, 3000L, 2);
    }

    /** Test constructor: write to a pre-built blob sink (the Cerbos-on-blob enforcement IT). */
    public PromotedBundleLoader(S3RuntimePolicySink s3Sink) {
        this.runtimePoliciesDir = "";
        this.tierSettleMs = 0L;
        this.emitPasses = 1;
        this.activationProbe = null;
        this.s3Sink = s3Sink;
    }

    /**
     * @param tierSettleMs the pause between scope-depth tiers (ancestors then children) — gives the PDP's
     *                     directory watcher time to observe and index each ancestor tier before its
     *                     children land, so no scoped child is ever presented (and rejected) before its
     *                     same-version ancestor. Sized for the SLOWEST watcher the runtime may sit behind
     *                     (a bind-mounted volume whose host→container inotify propagation is high-latency —
     *                     e.g. Docker Desktop VirtioFS). Control-plane latency only (promotion is off the
     *                     request path); configurable down where the watcher is fast. Tests may set 0.
     * @param emitPasses   how many times the whole ancestor-first write is repeated. A single write is
     *                     enough where every filesystem event is delivered; over a lossy watcher (VirtioFS
     *                     drops ~a third of host→container events) an idempotent re-write re-fires the
     *                     event for any file whose prior event was dropped, so the promoted bundle
     *                     converges into the index. Byte-identical re-writes ⇒ no spurious churn.
     */
    public PromotedBundleLoader(String runtimePoliciesDir, long tierSettleMs, int emitPasses) {
        this.runtimePoliciesDir = runtimePoliciesDir == null ? "" : runtimePoliciesDir.trim();
        this.tierSettleMs = Math.max(0L, tierSettleMs);
        this.emitPasses = Math.max(1, emitPasses);
        this.activationProbe = null;
        this.s3Sink = null;
    }

    /**
     * Production constructor. When {@code iam.policy-studio.runtime.s3.bucket} is set the promoted bundle is
     * written to that bucket (Cerbos {@code blob} driver polls it); otherwise the loader falls back to the
     * legacy watched-directory write. Every setting is bound (World B / §5: no hardcoded endpoint/bucket).
     */
    @org.springframework.beans.factory.annotation.Autowired
    public PromotedBundleLoader(
            @Value("${iam.policy-studio.runtime-policies-dir:}") String runtimePoliciesDir,
            @Value("${iam.policy-studio.runtime-load-tier-settle-ms:3000}") long tierSettleMs,
            @Value("${iam.policy-studio.runtime-load-emit-passes:2}") int emitPasses,
            CerbosRuntimeActivationProbe activationProbe,
            @Value("${iam.policy-studio.runtime.s3.bucket:}") String s3Bucket,
            @Value("${iam.policy-studio.runtime.s3.prefix:runtime}") String s3Prefix,
            @Value("${iam.policy-studio.runtime.s3.endpoint:}") String s3Endpoint,
            @Value("${iam.policy-studio.runtime.s3.region:us-east-1}") String s3Region,
            @Value("${iam.policy-studio.runtime.s3.path-style:true}") boolean s3PathStyle,
            @Value("${iam.policy-studio.runtime.s3.access-key:}") String s3AccessKey,
            @Value("${iam.policy-studio.runtime.s3.secret-key:}") String s3SecretKey) {
        this.runtimePoliciesDir = runtimePoliciesDir == null ? "" : runtimePoliciesDir.trim();
        this.tierSettleMs = Math.max(0L, tierSettleMs);
        this.emitPasses = Math.max(1, emitPasses);
        this.activationProbe = activationProbe;
        this.s3Sink = (s3Bucket == null || s3Bucket.isBlank())
                ? null
                : new S3RuntimePolicySink(s3Bucket, s3Prefix, s3Endpoint, s3Region, s3PathStyle,
                        s3AccessKey, s3SecretKey);
    }

    /**
     * True iff a runtime backend is configured (a blob bucket OR a watched directory) — otherwise
     * {@link #load} is a logged no-op.
     */
    public boolean isConfigured() {
        return s3Sink != null || !runtimePoliciesDir.isBlank();
    }

    /**
     * Observe the actual runtime policy store. Recovery uses this read, rather than inferring runtime
     * state from the tenant directory pointer, so an unavailable or unconfigured serving store fails closed.
     */
    public RuntimeStoreSnapshot snapshot() {
        if (s3Sink != null) {
            return RuntimeStoreSnapshot.of("s3", s3Sink.snapshotEntries());
        }
        if (runtimePoliciesDir.isBlank()) {
            throw new PromotedBundleLoadException("recovery", "<unconfigured>",
                    new IllegalStateException("runtime policy store is not configured"));
        }
        try {
            Path root = Path.of(runtimePoliciesDir);
            if (!Files.isDirectory(root)) {
                throw new IOException("runtime policy store is not a directory: " + root);
            }
            List<String> entries = new ArrayList<>();
            try (var paths = Files.walk(root)) {
                paths.filter(Files::isRegularFile).sorted().forEach(path -> {
                    try {
                        String relative = root.relativize(path).toString().replace('\\', '/');
                        String content = Files.readString(path, StandardCharsets.UTF_8);
                        entries.add(relative + "|" + sha256(content));
                    } catch (IOException e) {
                        throw new RuntimeStoreReadException(e);
                    }
                });
            } catch (RuntimeStoreReadException e) {
                throw e;
            }
            return RuntimeStoreSnapshot.of("disk", entries);
        } catch (RuntimeStoreReadException e) {
            throw new PromotedBundleLoadException("recovery", runtimePoliciesDir, e.getCause());
        } catch (IOException | RuntimeException e) {
            if (e instanceof PromotedBundleLoadException failure) throw failure;
            throw new PromotedBundleLoadException("recovery", runtimePoliciesDir, e);
        }
    }

    private static String sha256(String value) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256")
                    .digest(value.getBytes(StandardCharsets.UTF_8));
            StringBuilder out = new StringBuilder(digest.length * 2);
            for (byte b : digest) out.append(String.format("%02x", b));
            return out.toString();
        } catch (Exception e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }

    private static final class RuntimeStoreReadException extends RuntimeException {
        private RuntimeStoreReadException(IOException cause) { super(cause); }
    }

    public record RuntimeStoreSnapshot(String backend, int objectCount, String inventoryHash,
                                       List<String> entries) {
        static RuntimeStoreSnapshot of(String backend, List<String> entries) {
            String canonical = String.join("\n", entries);
            byte[] digest;
            try {
                digest = MessageDigest.getInstance("SHA-256")
                        .digest(canonical.getBytes(StandardCharsets.UTF_8));
            } catch (Exception e) {
                throw new IllegalStateException("SHA-256 unavailable", e);
            }
            StringBuilder hash = new StringBuilder(digest.length * 2);
            for (byte b : digest) hash.append(String.format("%02x", b));
            return new RuntimeStoreSnapshot(Objects.requireNonNull(backend), entries.size(), hash.toString(),
                    List.copyOf(entries));
        }
    }

    /**
     * Runtime publication barrier used before the tenant pointer is made visible. Blob-backed Cerbos polls
     * its bucket, and disk-backed Cerbos reloads asynchronously; this configured settle interval must be
     * longer than the serving PDP's poll/reload interval. Direct test constructors use zero delay.
     */
    public void awaitPublication(PolicyBundle bundle) {
        if (activationProbe != null) {
            activationProbe.awaitLoaded(bundle);
        }
    }

    /**
     * Write the promoted bundle's rendered (bundleId-stamped) policies into the runtime store Cerbos serves —
     * the S3 bucket (blob driver, polled) when a bucket is configured, otherwise the legacy watched
     * directory (disk driver). Returns the objects/files written (empty when no backend is configured).
     *
     * @throws PromotedBundleLoadException if the configured backend cannot be written (fail-closed)
     */
    public List<Path> load(PolicyBundle bundle) {
        if (!isConfigured()) {
            log.info("no runtime backend configured — skipping runtime load of promoted bundle '{}'. "
                    + "Set iam.policy-studio.runtime.s3.bucket (blob) or iam.policy-studio.runtime-policies-dir "
                    + "(disk) so the promotion reaches the serving PDP.", bundle.bundleId());
            return List.of();
        }

        // Select the complete rendered snapshot, then publish modules first and resource policies ancestor-first.
        //
        // renderedFiles() stamps the concrete bundleId into the version position; the StagingCandidateProbe
        // already verified every version-keyed rendered file carries it and no sentinel survives, so what
        // lands in the store is exactly what cerbos compile validated.
        //
        // Global modules are name-keyed rather than version-keyed. PolicyBundle.renderedFiles() therefore
        // versions every captured derived-role/exported-variable module name AND all imports with the same
        // content-addressed bundle id. Publish the complete rendered snapshot: old b_* policies keep importing
        // their old immutable module identity, while this bundle's modules coexist without duplicate names.
        List<BundleFile> writable = new ArrayList<>(bundle.renderedFiles());

        // ── Production: write to the blob bucket Cerbos polls. ──
        // A poll reads the WHOLE bucket snapshot and compiles it as one unit, so the per-file watch-event
        // ordering the disk path had to defend against does not arise. We still emit dependency-first (modules,
        // then root scope, then scoped children) so a poll that catches a partially-written prefix never sees
        // a child ahead of its ceiling. No inter-tier settle and no re-emit passes are needed: an object PUT is
        // atomic and the poll re-reads on the next tick.
        if (s3Sink != null) {
            List<BundleFile> ordered = new ArrayList<>(writable);
            ordered.sort(java.util.Comparator.comparingInt(f -> publicationTier(f.yaml())));
            LinkedHashMap<String, String> objects = new LinkedHashMap<>();
            for (BundleFile file : ordered) {
                objects.put(stagedFileName(bundle.bundleId(), file.path()), file.yaml());
            }
            List<String> keys = s3Sink.write(objects);
            log.info("Loaded promoted bundle '{}' into runtime blob bucket ({} object(s)) — Cerbos blob "
                    + "driver will poll and reload; version={} now enforceable, base default unchanged",
                    bundle.bundleId(), keys.size(), bundle.bundleId());
            return keys.stream().map(Path::of).collect(java.util.stream.Collectors.toList());
        }

        // ── Fallback / revert path: write to the Cerbos-watched directory (disk driver). ──
        try {
            Path dir = Path.of(runtimePoliciesDir);
            Files.createDirectories(dir);
            // A self-contained bundle carries a whole scope chain at the SAME version — the tenant child
            // (scope: "acme") AND its root ceiling (scope: "") — and the child declares the root as its
            // ancestor. Cerbos' watchForChanges processes each file's storage event as it lands and looks
            // the ancestor up in the CURRENT index: if the scoped child is indexed before its same-version
            // root, the compilation unit fails ("failed to load ancestor ... policy not found") and Cerbos
            // "maintains the last valid state" — leaving the promotion silently un-enforced. renderedFiles()
            // is path-sorted, so scoped children precede their root policy — child before ancestor,
            // exactly the losing order.
            //
            // Fix: write DEPENDENCY-FIRST, grouped into tiers (global module = -1, root scope "" = 0,
            // "acme" = 1, …), and settle briefly between tiers. Ordering alone is not enough — a single rapid
            // write burst coalesces into one watch batch the PDP may process child-first; the inter-tier
            // settle lets the watcher observe and index each ancestor tier before its children land, so no
            // scoped child is ever presented ahead of its same-version ancestor (verified against a live
            // pinned Cerbos with disk + watchForChanges, standalone and under full-suite load).
            java.util.SortedMap<Integer, List<BundleFile>> byDepth = new java.util.TreeMap<>();
            for (BundleFile file : writable) {
                byDepth.computeIfAbsent(publicationTier(file.yaml()), d -> new ArrayList<>()).add(file);
            }

            // Repeat the ancestor-first tiered write `emitPasses` times. The first pass loads the bundle;
            // each subsequent pass re-fires the storage event for every file (idempotent, byte-identical),
            // so any file whose event a lossy watcher dropped is re-presented — with its ancestors already
            // on disk — until the whole bundle has converged into the index.
            java.util.LinkedHashSet<Path> written = new java.util.LinkedHashSet<>();
            for (int pass = 0; pass < emitPasses; pass++) {
                int tiersRemaining = byDepth.size();
                for (List<BundleFile> tier : byDepth.values()) {
                    for (BundleFile file : tier) {
                        Path target = dir.resolve(stagedFileName(bundle.bundleId(), file.path()));
                        writeAtomically(target, file.yaml());
                        written.add(target);
                    }
                    if (--tiersRemaining > 0 && tierSettleMs > 0) {
                        settle(); // let the watcher index this ancestor tier before its children land
                    }
                }
                if (pass + 1 < emitPasses && tierSettleMs > 0) {
                    settle(); // space passes so a re-fired event is a distinct watch event
                }
            }
            log.info("Loaded promoted bundle '{}' into runtime policies dir '{}' ({} file(s)) — "
                    + "Cerbos watchForChanges will reload; version={} now enforceable, base default unchanged",
                    bundle.bundleId(), dir.toAbsolutePath(), written.size(), bundle.bundleId());
            return new ArrayList<>(written);
        } catch (IOException e) {
            throw new PromotedBundleLoadException(bundle.bundleId(), runtimePoliciesDir, e);
        }
    }

    /** Pause between scope-depth tiers so the PDP watcher indexes each ancestor tier before its children. */
    private void settle() {
        try {
            Thread.sleep(tierSettleMs);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    /**
     * Publish one policy object through a same-directory temporary file, then verify the exact bytes
     * visible at the Cerbos-watched path. A restart can therefore observe either the old complete
     * object or the new complete object, never a truncated YAML file.
     */
    private static void writeAtomically(Path target, String yaml) throws IOException {
        Path temporary = Files.createTempFile(target.getParent(), "." + target.getFileName(), ".publish");
        try {
            Files.writeString(temporary, yaml, StandardCharsets.UTF_8,
                    StandardOpenOption.TRUNCATE_EXISTING, StandardOpenOption.WRITE);
            try {
                Files.move(temporary, target, StandardCopyOption.ATOMIC_MOVE,
                        StandardCopyOption.REPLACE_EXISTING);
            } catch (AtomicMoveNotSupportedException unsupported) {
                Files.move(temporary, target, StandardCopyOption.REPLACE_EXISTING);
            }
            if (!yaml.equals(Files.readString(target, StandardCharsets.UTF_8))) {
                throw new IOException("runtime policy readback did not match the published bytes at " + target);
            }
        } finally {
            Files.deleteIfExists(temporary);
        }
    }

    /**
     * The scope depth of a rendered resource policy — {@code scope: ""} (root ceiling) = 0, {@code
     * scope: "acme"} = 1, {@code scope: "acme.eng"} = 2, … — used to order writes ancestor-first so a
     * scoped child is never indexed before its same-version ancestor during a watch reload. A file with no
     * {@code scope:} line sorts as root for this resource-only calculation; {@link #publicationTier} places
     * global modules ahead of it.
     */
    static int scopeDepth(String yaml) {
        java.util.regex.Matcher m = SCOPE_LINE.matcher(yaml);
        if (!m.find()) {
            return 0;
        }
        String scope = m.group(1).trim();
        if (scope.startsWith("\"") || scope.startsWith("'")) {
            scope = scope.substring(1, scope.length() - 1);
        }
        return scope.isBlank() ? 0 : scope.split("\\.").length;
    }

    /**
     * A bundle-versioned global module must be visible before a root policy imports it. Modules therefore
     * occupy tier -1, followed by root policies (0) and increasingly deep scoped children.
     */
    static int publicationTier(String yaml) {
        return GLOBAL_MODULE.matcher(yaml).find() ? -1 : scopeDepth(yaml);
    }

    /** Matches the resource-policy {@code scope:} line (quoted or bare), capturing the scope value. */
    private static final java.util.regex.Pattern SCOPE_LINE =
            java.util.regex.Pattern.compile("(?m)^\\s*scope:\\s*(\"[^\"]*\"|'[^']*'|\\S*)\\s*$");

    private static final java.util.regex.Pattern GLOBAL_MODULE =
            java.util.regex.Pattern.compile("(?m)^(?:derivedRoles|exportVariables):\\s*$");

    /** A filesystem-safe, bundle-namespaced file name so promoted versions coexist and re-promotion is idempotent. */
    private static String stagedFileName(String bundleId, String path) {
        String safeBundle = bundleId.replaceAll("[^A-Za-z0-9_.-]", "_");
        String safePath = path.replaceAll("[^A-Za-z0-9_.-]", "_");
        String name = safeBundle + "__" + safePath;
        if (!name.endsWith(".yaml") && !name.endsWith(".yml")) {
            name = name + ".yaml";
        }
        return name;
    }
}
