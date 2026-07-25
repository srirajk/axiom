package com.openwolf.iam.policystudio;

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
import java.util.TreeSet;
import java.util.stream.Stream;

/**
 * S5 (lifecycle-spine hardening) — derives the studio grounding <b>vocabulary</b> (resource kind, actions,
 * roles, approved imports) and the immutable <b>base ceiling</b> for a resource kind from the tenant-effective
 * Cerbos base policy bundle, so none of these are Java literals in the platform grounding provider.
 *
 * <p>The base resource policy ({@code <kind>_resource.yaml}, {@code scope: ""}) IS the ceiling every tenant
 * narrows from, and the imported derived-role modules ({@code business_derived_roles.yaml}) carry the
 * role→parentRoles expansion and the tenant-equality backstop. Reading them here mirrors the serving
 * discipline of compiling from manifest/config facts rather than embedding domain knowledge in Java: adding
 * an action, role, or ceiling tuple is a policy edit, not a code edit.
 *
 * <ul>
 *   <li><b>actions</b> — the union of {@code rules[].actions} across every resource policy for the kind
 *       (root ceiling + scoped children);</li>
 *   <li><b>roles</b> — the raw {@code rules[].roles} named across those policies, unioned with every
 *       {@code parentRoles} declared by the imported derived-role modules (so a role the ceiling reaches
 *       only through a derived role is still in the closed vocabulary);</li>
 *   <li><b>ceiling tuples</b> — for each ALLOW rule of the ROOT policy only, the cross-product of its
 *       actions with its roles ∪ (derivedRoles expanded to parentRoles) — exactly the base-allowed
 *       {@code (action, role)} surface a tenant child must be total over;</li>
 *   <li><b>carriesTenantEqualityBackstop</b> — whether the root policy imports a derived-role module whose
 *       condition carries {@code P.attr.tenant_id == R.attr.tenant_id};</li>
 *   <li><b>reservedIdentities</b> — immutable ROOT identities already present in the base bundle. Existing
 *       tenant children are replaceable by that tenant's next candidate and therefore are not reserved;</li>
 *   <li><b>frontDoorRoles</b> — ceiling roles whose granted action-set is a strict subset of the full
 *       action surface (i.e. they lack the management actions the admin/superuser roles hold) — the
 *       condition-gated "front door" the consequence matrix exercises with attribute negatives.</li>
 * </ul>
 */
public final class BaseBundleGrounding {

    private BaseBundleGrounding() {}

    /** The grounding facts derived from the base bundle for one resource kind. */
    public record Facts(
            String resourceKind,
            Set<String> actions,
            Set<String> roles,
            BaseCeiling ceiling,
            Set<String> approvedImports,
            Set<String> frontDoorRoles) {}

    /**
     * Read the base-bundle grounding for {@code resourceKind} from {@code baseBundleDir}.
     *
     * @throws IllegalStateException if the dir is missing or has no root resource policy for the kind
     */
    public static Facts read(Path baseBundleDir, String resourceKind) {
        if (resourceKind == null || resourceKind.isBlank()) {
            throw new IllegalArgumentException("resourceKind must be set");
        }
        if (!Files.isDirectory(baseBundleDir)) {
            throw new IllegalStateException("base bundle dir '" + baseBundleDir + "' is missing — cannot "
                    + "derive studio grounding for '" + resourceKind + "'");
        }

        Map<Path, Map<String, Object>> docs = readYamlDocs(baseBundleDir);

        // ── derived-role modules: definition → parentRoles (for ceiling expansion), module → all its
        //    parentRoles (for the roles vocabulary), and which modules carry the tenant-equality backstop ──
        Map<String, Set<String>> derivedParents = new LinkedHashMap<>();  // definition name → parentRoles
        Map<String, Set<String>> moduleParents = new LinkedHashMap<>();   // module name → all parentRoles
        Set<String> backstopModules = new LinkedHashSet<>();
        for (Map<String, Object> doc : docs.values()) {
            Map<String, Object> module = asMap(doc.get("derivedRoles"));
            if (module == null) {
                continue;
            }
            String moduleName = str(module.get("name"));
            Set<String> allParents = moduleName == null ? new LinkedHashSet<>()
                    : moduleParents.computeIfAbsent(moduleName, k -> new LinkedHashSet<>());
            boolean moduleHasBackstop = false;
            for (Object def : seq(module.get("definitions"))) {
                Map<String, Object> d = asMap(def);
                if (d == null) {
                    continue;
                }
                String name = str(d.get("name"));
                Set<String> parents = new LinkedHashSet<>(strList(d.get("parentRoles")));
                allParents.addAll(parents);
                if (name != null) {
                    derivedParents.computeIfAbsent(name, k -> new LinkedHashSet<>()).addAll(parents);
                }
                if (carriesTenantEquality(flatten(d.get("condition")))) {
                    moduleHasBackstop = true;
                }
            }
            if (moduleName != null && moduleHasBackstop) {
                backstopModules.add(moduleName);
            }
        }

        // ── resource policies for the kind: actions/roles/imports vocab (all scopes) + ceiling (root only) ──
        Set<String> actions = new TreeSet<>();
        Set<String> rawRoles = new TreeSet<>();
        Set<String> imports = new TreeSet<>();
        Set<String> reservedIdentities = new TreeSet<>();
        Set<BaseCeiling.Tuple> tuples = new LinkedHashSet<>();
        Map<String, Set<String>> ceilingActionsByRole = new LinkedHashMap<>();
        boolean sawRoot = false;
        boolean rootBackstop = false;

        for (Map<String, Object> doc : docs.values()) {
            Map<String, Object> rp = asMap(doc.get("resourcePolicy"));
            if (rp == null || !resourceKind.equals(str(rp.get("resource")))) {
                continue;
            }
            String scope = rp.get("scope") == null ? "" : str(rp.get("scope"));
            boolean isRoot = scope == null || scope.isBlank();
            List<String> policyImports = strList(rp.get("importDerivedRoles"));
            imports.addAll(policyImports);
            if (isRoot) {
                reservedIdentities.add(resourceKind + "@");
            }

            for (Object r : seq(rp.get("rules"))) {
                Map<String, Object> rule = asMap(r);
                if (rule == null) {
                    continue;
                }
                List<String> ruleActions = strList(rule.get("actions"));
                actions.addAll(ruleActions);
                rawRoles.addAll(strList(rule.get("roles")));
                Set<String> expanded = expandRoles(strList(rule.get("roles")),
                        strList(rule.get("derivedRoles")), derivedParents);
                if (isRoot && "EFFECT_ALLOW".equals(str(rule.get("effect")))) {
                    for (String action : ruleActions) {
                        for (String role : expanded) {
                            tuples.add(new BaseCeiling.Tuple(action, role));
                            ceilingActionsByRole.computeIfAbsent(role, k -> new TreeSet<>()).add(action);
                        }
                    }
                }
            }
            if (isRoot) {
                sawRoot = true;
                rootBackstop = policyImports.stream().anyMatch(backstopModules::contains);
            }
        }

        if (!sawRoot) {
            throw new IllegalStateException("no root ('scope: \"\"') resource policy for kind '" + resourceKind
                    + "' under '" + baseBundleDir + "' — cannot derive a base ceiling");
        }

        // roles vocabulary: raw roles named anywhere for the kind ∪ every parentRole of an imported module
        // (so a role the ceiling reaches only through a derived role is still in the closed vocabulary).
        Set<String> roles = new TreeSet<>(rawRoles);
        for (String moduleName : imports) {
            roles.addAll(moduleParents.getOrDefault(moduleName, Set.of()));
        }

        // front-door roles: ceiling roles that do NOT hold the full action surface (they are the
        // condition-gated roles, as opposed to the unconditional admin/superuser roles).
        Set<String> frontDoor = new TreeSet<>();
        for (Map.Entry<String, Set<String>> e : ceilingActionsByRole.entrySet()) {
            if (!e.getValue().equals(actions)) {
                frontDoor.add(e.getKey());
            }
        }

        BaseCeiling ceiling = new BaseCeiling(resourceKind, tuples, rootBackstop, reservedIdentities);
        return new Facts(resourceKind, Set.copyOf(actions), Set.copyOf(roles), ceiling,
                Set.copyOf(imports), Set.copyOf(frontDoor));
    }

    private static Set<String> expandRoles(List<String> rawRoles, List<String> derivedRoles,
                                           Map<String, Set<String>> derivedParents) {
        Set<String> out = new LinkedHashSet<>(rawRoles);
        for (String dr : derivedRoles) {
            out.addAll(derivedParents.getOrDefault(dr, Set.of()));
        }
        return out;
    }

    /** A condition carries the tenant-equality backstop iff it compares P.attr.tenant_id to R.attr.tenant_id. */
    private static boolean carriesTenantEquality(String conditionText) {
        return conditionText.contains("P.attr.tenant_id")
                && conditionText.contains("R.attr.tenant_id")
                && conditionText.contains("==");
    }

    // ── yaml plumbing (SafeConstructor, skip test suites) ─────────────────────────────────────────

    private static Map<Path, Map<String, Object>> readYamlDocs(Path baseBundleDir) {
        Map<Path, Map<String, Object>> out = new LinkedHashMap<>();
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
                            out.put(p, asMap(parseYaml(Files.readString(p))));
                        } catch (IOException e) {
                            throw new IllegalStateException("failed to read base policy '" + p + "'", e);
                        }
                    });
        } catch (IOException e) {
            throw new IllegalStateException("failed to scan base bundle dir '" + baseBundleDir + "'", e);
        }
        out.values().removeIf(m -> m == null);
        return out;
    }

    private static Object parseYaml(String yaml) {
        return new Yaml(new SafeConstructor(new LoaderOptions())).load(yaml);
    }

    /** Every scalar string leaf under a parsed node, space-joined — enough to scan a condition. */
    private static String flatten(Object node) {
        List<String> leaves = new ArrayList<>();
        collect(node, leaves);
        return String.join(" ", leaves);
    }

    private static void collect(Object node, List<String> out) {
        switch (node) {
            case String s -> out.add(s);
            case Map<?, ?> m -> m.values().forEach(v -> collect(v, out));
            case List<?> l -> l.forEach(v -> collect(v, out));
            case null -> { }
            default -> out.add(String.valueOf(node));
        }
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> asMap(Object o) {
        return o instanceof Map<?, ?> m ? (Map<String, Object>) m : null;
    }

    private static List<?> seq(Object o) {
        return o instanceof List<?> l ? l : List.of();
    }

    private static String str(Object o) {
        return o == null ? null : String.valueOf(o);
    }

    private static List<String> strList(Object o) {
        if (!(o instanceof List<?> list)) {
            return List.of();
        }
        List<String> out = new ArrayList<>(list.size());
        for (Object e : list) {
            out.add(String.valueOf(e));
        }
        return out;
    }
}
