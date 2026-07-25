package com.openwolf.iam.policystudio.lifecycle;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.yaml.snakeyaml.LoaderOptions;
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.constructor.SafeConstructor;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.stream.Stream;

/**
 * S3 (lifecycle-spine hardening) — captures the <b>whole self-contained policy set</b> a candidate bundle
 * needs to compile and evaluate for one resource kind, so its {@code bundleId} hashes a complete universe
 * rather than a lone tenant child that silently relies on a mutable external base directory.
 *
 * <p>For a resource kind it captures, from the immutable base bundle directory:
 * <ul>
 *   <li><b>every scope-chain policy</b> — the root ceiling + every scoped resource policy whose
 *       {@code resource} matches the requested platform kind and tenant scope;</li>
 *   <li><b>every imported derived-roles module</b> — resolved by name from the scope-chain policies'
 *       {@code importDerivedRoles};</li>
 *   <li>(exported <b>variables</b> modules imported via {@code variables.import}, if any are declared).</li>
 * </ul>
 * Test suites ({@code *_test.yaml}, anything under a {@code tests/} directory) are excluded — they are
 * assertions about the policies, not the policies. Every captured resource policy is authored into the
 * bundle in <b>version-sentinel form</b> ({@code version: "default"} → {@link
 * BundleCanonicalizer#BUNDLE_VERSION_SENTINEL}); derived-roles / variables modules are global (keyed by
 * name, not version) and are captured verbatim.
 *
 * <p>The raw file bytes (comments and all) are preserved, so a one-byte change to any captured policy,
 * derived-role, or variable changes the bundle id — exactly the property that makes the promotion CAS and
 * the {@code cerbos compile}-from-captured-contents trustworthy.
 */
@Component
public class SelfContainedBundleAssembler {

    private static final Logger log = LoggerFactory.getLogger(SelfContainedBundleAssembler.class);

    /** Stamps {@code version: "default"} (any quoting) to the reproducible bundle-version sentinel. */
    private static final String VERSION_DEFAULT_LINE =
            "(?m)^(\\s*version:\\s*)(\"default\"|'default'|default)\\s*$";

    private final Path baseBundleDir;

    public SelfContainedBundleAssembler(
            @Value("${iam.policy-studio.base-bundle-dir:/app/platform-policy/policies}") String baseBundleDir) {
        Path configured = Path.of(baseBundleDir);
        this.baseBundleDir = Files.isDirectory(configured)
                ? configured
                : Path.of("..").resolve(baseBundleDir).normalize();
    }

    Path baseBundleDir() {
        return baseBundleDir;
    }

    /**
     * Capture the self-contained base set (scope-chain + imported derived-roles / variables) for a
     * resource kind, as version-sentinel {@link BundleFile}s in stable path order. The authored tenant
     * child is NOT included here — the caller appends it.
     *
     * @throws IllegalStateException if the base dir is missing or no root policy exists for the kind
     */
    public List<BundleFile> captureScopeChain(String resourceKind) {
        if (resourceKind == null || resourceKind.isBlank()) {
            throw new IllegalArgumentException("resourceKind must be set");
        }
        if (!Files.isDirectory(baseBundleDir)) {
            throw new IllegalStateException("base bundle dir '" + baseBundleDir + "' is missing — cannot "
                    + "assemble a self-contained candidate bundle for '" + resourceKind + "'");
        }

        Map<Path, String> allPolicies = readPolicyFiles();

        // ── 1. scope-chain: every resource policy whose `resource` == the kind. ──
        Map<String, BundleFile> captured = new LinkedHashMap<>(); // bundle path → file (dedupe, then sort)
        Set<String> importedDerivedRoleNames = new LinkedHashSet<>();
        Set<String> importedVariableNames = new LinkedHashSet<>();
        boolean sawRoot = false;
        for (Map.Entry<Path, String> e : allPolicies.entrySet()) {
            Map<String, Object> doc = parse(e.getValue());
            Map<String, Object> resourcePolicy = asMap(doc.get("resourcePolicy"));
            if (resourcePolicy == null || !resourceKind.equals(String.valueOf(resourcePolicy.get("resource")))) {
                continue;
            }
            String bundlePath = "policies/" + e.getKey().getFileName();
            captured.put(bundlePath, new BundleFile(bundlePath, stampVersion(e.getValue())));
            importedDerivedRoleNames.addAll(stringList(resourcePolicy.get("importDerivedRoles")));
            importedVariableNames.addAll(importedVariables(resourcePolicy));
            if (String.valueOf(resourcePolicy.getOrDefault("scope", "")).isEmpty()) {
                sawRoot = true;
            }
        }
        if (captured.isEmpty() || !sawRoot) {
            throw new IllegalStateException("no root resource policy for kind '" + resourceKind
                    + "' under '" + baseBundleDir + "' — cannot build a self-contained bundle");
        }

        // ── 2. imported derived-roles / variables modules, resolved by name. ──
        for (Map.Entry<Path, String> e : allPolicies.entrySet()) {
            Map<String, Object> doc = parse(e.getValue());
            String derivedName = moduleName(doc.get("derivedRoles"));
            String variableName = moduleName(doc.get("exportVariables"));
            boolean include = (derivedName != null && importedDerivedRoleNames.contains(derivedName))
                    || (variableName != null && importedVariableNames.contains(variableName));
            if (include) {
                String bundlePath = "policies/" + e.getKey().getFileName();
                // Derived-roles / variable modules are global (name-keyed, not version-keyed): capture the
                // exact bytes so a change to them changes the bundle id.
                captured.putIfAbsent(bundlePath, new BundleFile(bundlePath, e.getValue()));
            }
        }

        List<BundleFile> files = new ArrayList<>(captured.values());
        files.sort((a, b) -> a.path().compareTo(b.path()));
        log.debug("Assembled self-contained base for kind '{}': {} file(s) (imports: derivedRoles={}, variables={})",
                resourceKind, files.size(), importedDerivedRoleNames, importedVariableNames);
        return files;
    }

    /**
     * Capture the complete immutable base policy universe for a tenant bundle: every resource policy
     * (all resource kinds and scopes) plus every derived-role/variable module imported by any of them.
     * C5 has one live {@code activePolicyVersion} per tenant, so a promotable bundle cannot contain only
     * the resource kind most recently edited; every authorization call pinned to that version must resolve.
     */
    public List<BundleFile> captureFullPolicySet() {
        if (!Files.isDirectory(baseBundleDir)) {
            throw new IllegalStateException("base bundle dir '" + baseBundleDir
                    + "' is missing — cannot assemble a full tenant policy snapshot");
        }

        Map<Path, String> allPolicies = readPolicyFiles();
        Map<String, BundleFile> captured = new LinkedHashMap<>();
        Set<String> importedDerivedRoleNames = new LinkedHashSet<>();
        Set<String> importedVariableNames = new LinkedHashSet<>();
        Set<String> resources = new LinkedHashSet<>();
        Set<String> resourcesWithRoot = new LinkedHashSet<>();

        for (Map.Entry<Path, String> e : allPolicies.entrySet()) {
            Map<String, Object> doc = parse(e.getValue());
            Map<String, Object> resourcePolicy = asMap(doc.get("resourcePolicy"));
            if (resourcePolicy == null) {
                continue;
            }
            String resource = String.valueOf(resourcePolicy.get("resource"));
            resources.add(resource);
            if (String.valueOf(resourcePolicy.getOrDefault("scope", "")).isEmpty()) {
                resourcesWithRoot.add(resource);
            }
            String bundlePath = "policies/" + e.getKey().getFileName();
            captured.put(bundlePath, new BundleFile(bundlePath, stampVersion(e.getValue())));
            importedDerivedRoleNames.addAll(stringList(resourcePolicy.get("importDerivedRoles")));
            importedVariableNames.addAll(importedVariables(resourcePolicy));
        }
        if (resources.isEmpty()) {
            throw new IllegalStateException("no resource policies under '" + baseBundleDir
                    + "' — cannot build a full tenant policy snapshot");
        }
        Set<String> missingRoots = new LinkedHashSet<>(resources);
        missingRoots.removeAll(resourcesWithRoot);
        if (!missingRoots.isEmpty()) {
            throw new IllegalStateException("resource kinds without a root ceiling under '" + baseBundleDir
                    + "': " + missingRoots);
        }

        for (Map.Entry<Path, String> e : allPolicies.entrySet()) {
            Map<String, Object> doc = parse(e.getValue());
            String derivedName = moduleName(doc.get("derivedRoles"));
            String variableName = moduleName(doc.get("exportVariables"));
            boolean include = (derivedName != null && importedDerivedRoleNames.contains(derivedName))
                    || (variableName != null && importedVariableNames.contains(variableName));
            if (include) {
                String bundlePath = "policies/" + e.getKey().getFileName();
                captured.putIfAbsent(bundlePath, new BundleFile(bundlePath, e.getValue()));
            }
        }

        List<BundleFile> files = new ArrayList<>(captured.values());
        files.sort((a, b) -> a.path().compareTo(b.path()));
        log.debug("Assembled full tenant policy base: {} file(s), resourceKinds={}", files.size(), resources);
        return files;
    }

    // ── plumbing ──────────────────────────────────────────────────────────────────────────────────

    private Map<Path, String> readPolicyFiles() {
        Map<Path, String> out = new LinkedHashMap<>();
        try (Stream<Path> paths = Files.walk(baseBundleDir)) {
            paths.filter(Files::isRegularFile)
                    .filter(p -> {
                        String n = p.getFileName().toString();
                        return (n.endsWith(".yaml") || n.endsWith(".yml"))
                                && !n.endsWith("_test.yaml") && !n.endsWith("_test.yml");
                    })
                    .filter(p -> !baseBundleDir.relativize(p).toString().replace('\\', '/').contains("tests/"))
                    .sorted()
                    .forEach(p -> {
                        try {
                            out.put(p, Files.readString(p));
                        } catch (IOException ex) {
                            throw new IllegalStateException("failed to read base policy '" + p + "'", ex);
                        }
                    });
        } catch (IOException e) {
            throw new IllegalStateException("failed to scan base bundle dir '" + baseBundleDir + "'", e);
        }
        return out;
    }

    private static String stampVersion(String yaml) {
        return yaml.replaceFirst(VERSION_DEFAULT_LINE,
                "$1" + Matcher.quoteReplacement("\"" + BundleCanonicalizer.BUNDLE_VERSION_SENTINEL + "\""));
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> parse(String yaml) {
        Yaml y = new Yaml(new SafeConstructor(new LoaderOptions()));
        Object loaded = y.load(yaml);
        return loaded instanceof Map<?, ?> m ? (Map<String, Object>) m : Map.of();
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> asMap(Object o) {
        return o instanceof Map<?, ?> m ? (Map<String, Object>) m : null;
    }

    private static String moduleName(Object module) {
        Map<String, Object> m = asMap(module);
        return m == null || m.get("name") == null ? null : String.valueOf(m.get("name"));
    }

    private static List<String> stringList(Object o) {
        if (!(o instanceof List<?> list)) {
            return List.of();
        }
        List<String> out = new ArrayList<>(list.size());
        for (Object e : list) {
            out.add(String.valueOf(e));
        }
        return out;
    }

    /** Cerbos exported-variable imports live under {@code variables.import} on a resource policy. */
    private static List<String> importedVariables(Map<String, Object> resourcePolicy) {
        Map<String, Object> variables = asMap(resourcePolicy.get("variables"));
        return variables == null ? List.of() : stringList(variables.get("import"));
    }
}
