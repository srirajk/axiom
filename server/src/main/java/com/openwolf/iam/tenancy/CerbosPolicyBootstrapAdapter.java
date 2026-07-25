package com.openwolf.iam.tenancy;

import com.openwolf.iam.policystudio.CanonicalPolicyWriter;
import com.openwolf.iam.policystudio.CerbosCompileGate;
import com.openwolf.iam.policystudio.BaseBundleGrounding;
import com.openwolf.iam.policystudio.PolicyIR;
import com.openwolf.iam.policystudio.lifecycle.BundleCanonicalizer;
import com.openwolf.iam.policystudio.lifecycle.BundleFile;
import com.openwolf.iam.policystudio.lifecycle.BundleTestMetadata;
import com.openwolf.iam.policystudio.lifecycle.PolicyBundle;
import com.openwolf.iam.policystudio.lifecycle.ResourcePolicyIdentity;
import com.openwolf.iam.policystudio.lifecycle.SelfContainedBundleAssembler;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.yaml.snakeyaml.Yaml;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.regex.Pattern;
import java.util.stream.Stream;

/**
 * The real Cerbos policy-bootstrap adapter (Axiom B4). Builds a fresh tenant's deny-all bundle from
 * the current approved base ceiling and B1's parental-consent posture, WITHOUT mutating the live
 * bundle:
 *
 * <ol>
 *   <li>Read every root resource policy and derive every base-ceiling {@code (action, role)} tuple,
 *       including roles expanded from imported derived-role modules.
 *   <li>For each, emit a {@code tenant_&lt;id&gt;_&lt;resource&gt;.yaml} that {@code EFFECT_DENY}s the exact
 *       same tuple set under {@code scope: &lt;tenantId&gt;} and
 *       {@code SCOPE_PERMISSIONS_REQUIRE_PARENTAL_CONSENT_FOR_ALLOWS} — so nothing falls through and
 *       the fresh tenant denies EVERYTHING until a reviewed total restriction policy is promoted.
 *   <li>Materialize the normal C5 full bundle (all roots/scopes/modules, every exact tenant deny child,
 *       and manifest refs) so its stable identity is a concrete {@code b_*} version.
 *   <li>Stage the complete rendered bundle under {@code &lt;stagingRoot&gt;/&lt;tenant&gt;/&lt;b_*&gt;/}, alongside
 *       existing versions; the live bundle is never touched, no empty scope policy is ever written.
 *   <li>Probe the self-contained full bundle with the pinned Cerbos in an
 *       ephemeral {@code docker run --rm} (reusing {@link CerbosCompileGate}) — never the running PDP.
 * </ol>
 *
 * <p>The tenant-child grammar mirrors Axiom's canonical tenant claim grammar.
 */
@Component
public class CerbosPolicyBootstrapAdapter implements PolicyBootstrapAdapter {

    private static final Logger log = LoggerFactory.getLogger(CerbosPolicyBootstrapAdapter.class);

    private static final String API_VERSION = "api.cerbos.dev/v1";
    private static final String POLICY_VERSION_FIELD = BundleCanonicalizer.BUNDLE_VERSION_SENTINEL;
    private static final String PARENTAL_CONSENT = "SCOPE_PERMISSIONS_REQUIRE_PARENTAL_CONSENT_FOR_ALLOWS";
    private static final String DENY = "EFFECT_DENY";
    private static final Pattern RESOURCE_FILE = Pattern.compile(".*_resource\\.ya?ml");
    // Same canonical tenant grammar as TenantClaims — fail closed on anything else.
    private static final Pattern CANONICAL_TENANT_ID = Pattern.compile("[a-z0-9][a-z0-9-]{0,62}");

    private final CanonicalPolicyWriter writer;
    private final CerbosCompileGate compileGate;
    private final String baseBundleDir;
    private final String stagingRootDir;
    private final String platformContractPath;
    private final SelfContainedBundleAssembler assembler;
    private final BundleCanonicalizer canonicalizer;

    @org.springframework.beans.factory.annotation.Autowired
    public CerbosPolicyBootstrapAdapter(
            CanonicalPolicyWriter writer,
            CerbosCompileGate compileGate,
            SelfContainedBundleAssembler assembler,
            BundleCanonicalizer canonicalizer,
            @Value("${iam.policy-studio.base-bundle-dir:/app/platform-policy/policies}") String baseBundleDir,
            @Value("${iam.tenancy.policy-staging-dir:build/tenant-policy-staging}") String stagingRootDir,
            @Value("${iam.policy-studio.platform-contract-path:/app/platform-contract/axiom-platform-contract.json}")
            String platformContractPath) {
        this.writer = writer;
        this.compileGate = compileGate;
        this.assembler = assembler;
        this.canonicalizer = canonicalizer;
        this.baseBundleDir = baseBundleDir;
        this.stagingRootDir = stagingRootDir;
        this.platformContractPath = platformContractPath;
    }

    /** Convenience constructor for focused tests; still builds the same normal full C5 bundle. */
    public CerbosPolicyBootstrapAdapter(
            CanonicalPolicyWriter writer,
            CerbosCompileGate compileGate,
            String baseBundleDir,
            String stagingRootDir) {
        this(writer, compileGate, new SelfContainedBundleAssembler(baseBundleDir), new BundleCanonicalizer(),
                baseBundleDir, stagingRootDir, "platform-contract/axiom-platform-contract.json");
    }

    @Override
    public TenantBootstrapBundle stage(String tenantId) {
        if (tenantId == null || !CANONICAL_TENANT_ID.matcher(tenantId).matches()) {
            throw new ProvisioningException("illegal tenant id (fails canonical grammar): " + tenantId);
        }
        Path base = resolveBaseBundleDir();
        List<Ceiling> ceilings = readCeilings(base);
        if (ceilings.isEmpty()) {
            throw new ProvisioningException("no root base-ceiling resource policies found under " + base);
        }

        // Deterministic order (by resource) so the content hash is stable across runs.
        Map<String, String> childByResource = new TreeMap<>();
        for (Ceiling ceiling : ceilings) {
            childByResource.put(ceiling.resource(), writer.write(denyAll(tenantId, ceiling)));
        }
        Map<String, BundleFile> byPath = new TreeMap<>();
        for (BundleFile file : assembler.captureFullPolicySet()) {
            byPath.put(file.path(), file);
        }
        for (Map.Entry<String, String> child : childByResource.entrySet()) {
            BundleFile tenantChild = new BundleFile(
                    "policies/" + child.getKey() + "@" + tenantId + ".yaml", child.getValue());
            ResourcePolicyIdentity.putReplacing(byPath, tenantChild);
        }
        List<BundleFile> files = new ArrayList<>(byPath.values());
        files.sort(java.util.Comparator.comparing(BundleFile::path));
        String fixtureHash = contentHash(childByResource);
        int tupleCount = ceilings.stream().mapToInt(c -> c.rules().stream()
                .mapToInt(r -> r.actions().size() * r.roles().size()).sum()).sum();
        PolicyBundle policyBundle = PolicyBundle.materialize(
                tenantId,
                files,
                readPlatformContractRef(),
                new BundleTestMetadata(fixtureHash, tupleCount,
                        "b1-exact-deny-all-bootstrap", "deterministic-totality+cerbos-compile"),
                canonicalizer);
        String policyVersion = policyBundle.bundleId();

        Map<String, String> renderedChildren = new TreeMap<>();
        childByResource.forEach((resource, yaml) ->
                renderedChildren.put(resource, yaml.replace(POLICY_VERSION_FIELD, policyVersion)));

        Path stagingDir = resolveStagingRoot().resolve(tenantId).resolve(policyVersion);
        try {
            Files.createDirectories(stagingDir);
            for (BundleFile file : policyBundle.renderedFiles()) {
                Path staged = stagingDir.resolve(Path.of(file.path()).getFileName().toString());
                Files.writeString(staged, file.yaml(), StandardCharsets.UTF_8);
            }
        } catch (IOException e) {
            throw new ProvisioningException("could not stage bootstrap bundle for '" + tenantId + "'", e);
        }
        log.info("Staged deny-all bootstrap for tenant '{}' — version {} ({} resource children) at {}",
                tenantId, policyVersion, childByResource.size(), stagingDir);
        return new TenantBootstrapBundle(
                tenantId, policyVersion, stagingDir, renderedChildren, policyBundle);
    }

    @Override
    public void probe(TenantBootstrapBundle bundle) {
        if (!isProbeAvailable()) {
            log.warn("Cerbos compile gate unavailable — bootstrap bundle {} for tenant '{}' verified by "
                            + "deterministic deny-all totality only, NOT compile-probed (seam).",
                    bundle.policyVersion(), bundle.tenantId());
            return;
        }
        CerbosCompileGate.CompileOutcome outcome = compileGate.compile(bundle.policyBundle().renderedFiles());
        if (!outcome.success()) {
            throw new ProvisioningException("cerbos probe rejected full bootstrap bundle for tenant '"
                    + bundle.tenantId() + "':\n" + outcome.output());
        }
        log.info("Cerbos-probed bootstrap bundle {} for tenant '{}' ({} children compile clean)",
                bundle.policyVersion(), bundle.tenantId(), bundle.childByResource().size());
    }

    @Override
    public boolean isProbeAvailable() {
        return compileGate.isAvailable();
    }

    /**
     * H6 compensation — delete the staged (never-activated) version directory for a FAILED provision,
     * and prune the now-empty tenant staging root. Best-effort and idempotent: a missing directory is
     * a no-op. The live bundle is never under the staging root, so this can never touch it.
     */
    @Override
    public void discardStaged(TenantBootstrapBundle bundle) {
        if (bundle == null || bundle.stagingDir() == null) {
            return;
        }
        Path stagingDir = bundle.stagingDir();
        try {
            deleteRecursively(stagingDir);
            // Prune the tenant-level parent (…/staging/<tenant>) if this was its last staged version.
            Path tenantDir = stagingDir.getParent();
            if (tenantDir != null && Files.isDirectory(tenantDir)) {
                try (Stream<Path> siblings = Files.list(tenantDir)) {
                    if (siblings.findAny().isEmpty()) {
                        Files.deleteIfExists(tenantDir);
                    }
                }
            }
            log.info("H6 compensation: discarded staged bootstrap bundle {} for tenant '{}' at {}",
                    bundle.policyVersion(), bundle.tenantId(), stagingDir);
        } catch (IOException e) {
            // Best-effort: log and continue — the tenant is already absent from the directory (fail-closed).
            log.warn("H6 compensation: could not fully discard staged bundle {} for tenant '{}' at {}: {}",
                    bundle.policyVersion(), bundle.tenantId(), stagingDir, e.toString());
        }
    }

    private static void deleteRecursively(Path root) throws IOException {
        if (!Files.exists(root)) {
            return;
        }
        try (Stream<Path> walk = Files.walk(root)) {
            walk.sorted(java.util.Comparator.reverseOrder()).forEach(p -> {
                try {
                    Files.deleteIfExists(p);
                } catch (IOException e) {
                    throw new UncheckedIOException(e);
                }
            });
        } catch (UncheckedIOException e) {
            throw e.getCause();
        }
    }

    // ── deny-all construction ────────────────────────────────────────────────────────────────

    private PolicyIR denyAll(String tenantId, Ceiling ceiling) {
        List<PolicyIR.Rule> rules = new ArrayList<>();
        for (Ceiling.RuleTuple t : ceiling.rules()) {
            rules.add(new PolicyIR.Rule(t.actions(), DENY, t.roles(), List.of(), null));
        }
        return new PolicyIR(API_VERSION, POLICY_VERSION_FIELD, ceiling.resource(), tenantId,
                PARENTAL_CONSENT, List.of(), rules);
    }

    @SuppressWarnings("unchecked")
    private List<Ceiling> readCeilings(Path base) {
        List<Ceiling> ceilings = new ArrayList<>();
        try (Stream<Path> files = Files.list(base)) {
            List<Path> rootFiles = files
                    .filter(p -> RESOURCE_FILE.matcher(p.getFileName().toString()).matches())
                    .sorted()
                    .toList();
            Yaml yaml = new Yaml();
            for (Path p : rootFiles) {
                Map<String, Object> doc;
                try {
                    doc = yaml.load(Files.readString(p, StandardCharsets.UTF_8));
                } catch (IOException e) {
                    throw new UncheckedIOException(e);
                }
                Map<String, Object> rp = (Map<String, Object>) doc.get("resourcePolicy");
                if (rp == null) continue;
                String resource = String.valueOf(rp.get("resource"));
                BaseBundleGrounding.Facts grounded = BaseBundleGrounding.read(base, resource);
                List<Ceiling.RuleTuple> rules = grounded.ceiling().tuples().stream()
                        .sorted((a, b) -> (a.action() + "@" + a.role())
                                .compareTo(b.action() + "@" + b.role()))
                        .map(t -> new Ceiling.RuleTuple(List.of(t.action()), List.of(t.role())))
                        .toList();
                if (rules.isEmpty()) {
                    throw new ProvisioningException("root policy for resource '" + resource
                            + "' has no ALLOW ceiling tuples; cannot construct an exact total deny child");
                }
                ceilings.add(new Ceiling(resource, rules));
            }
        } catch (IOException e) {
            throw new ProvisioningException("could not read base ceiling from " + base, e);
        }
        return ceilings;
    }

    private String contentHash(Map<String, String> childByResource) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            // TreeMap iteration is sorted → stable input regardless of insertion order.
            for (Map.Entry<String, String> e : new TreeMap<>(childByResource).entrySet()) {
                md.update(e.getKey().getBytes(StandardCharsets.UTF_8));
                md.update((byte) 0);
                md.update(e.getValue().getBytes(StandardCharsets.UTF_8));
                md.update((byte) 0);
            }
            return HexFormat.of().formatHex(md.digest());
        } catch (java.security.NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }

    /** The only grounding reference in AXM-1 is the versioned platform contract. */
    private List<String> readPlatformContractRef() {
        Path contract = resolveExistingFile(platformContractPath,
                () -> new ProvisioningException("platform contract not found: " + platformContractPath));
        try {
            return List.of(contract.getFileName() + "#sha256=" + sha256(Files.readAllBytes(contract)));
        } catch (IOException e) {
            throw new ProvisioningException("could not read platform contract " + contract, e);
        }
    }

    private static String sha256(byte[] bytes) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));
        } catch (java.security.NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }

    private Path resolveBaseBundleDir() {
        return resolveExisting(baseBundleDir,
                () -> new ProvisioningException("base bundle dir not found: " + baseBundleDir));
    }

    private Path resolveStagingRoot() {
        Path direct = Path.of(stagingRootDir);
        if (direct.isAbsolute()) return direct;
        // Anchor a relative staging root at the same repo root the base bundle resolves under, so
        // staging is stable no matter the working directory a test/JVM is launched from.
        Path base = resolveBaseBundleDir();
        return relativeStagingRoot(base, stagingRootDir);
    }

    static Path relativeStagingRoot(Path base, String configured) {
        Path direct = Path.of(configured);
        Path repoRoot = base.getParent() != null && base.getParent().getParent() != null
                ? base.getParent().getParent()
                : Path.of("").toAbsolutePath();
        return repoRoot.resolve(direct).normalize();
    }

    /** Resolve a possibly-relative path, walking up from CWD to find it when not directly present. */
    private static Path resolveExisting(String configured, java.util.function.Supplier<RuntimeException> onMissing) {
        Path direct = Path.of(configured);
        if (Files.isDirectory(direct)) return direct.toAbsolutePath().normalize();
        Path cursor = Path.of("").toAbsolutePath();
        for (int i = 0; i < 6 && cursor != null; i++) {
            Path candidate = cursor.resolve(configured);
            if (Files.isDirectory(candidate)) return candidate.normalize();
            cursor = cursor.getParent();
        }
        throw onMissing.get();
    }

    private static Path resolveExistingFile(String configured, java.util.function.Supplier<RuntimeException> onMissing) {
        Path direct = Path.of(configured);
        if (Files.isRegularFile(direct)) return direct.toAbsolutePath().normalize();
        Path cursor = Path.of("").toAbsolutePath();
        for (int i = 0; i < 6 && cursor != null; i++) {
            Path candidate = cursor.resolve(configured);
            if (Files.isRegularFile(candidate)) return candidate.normalize();
            cursor = cursor.getParent();
        }
        throw onMissing.get();
    }

    /** One base resource-ceiling: the resource kind and its enumerated {@code (actions, roles)} tuples. */
    private record Ceiling(String resource, List<RuleTuple> rules) {
        record RuleTuple(List<String> actions, List<String> roles) {}
    }
}
