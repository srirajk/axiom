package com.openwolf.iam.policystudio.lifecycle;

import org.yaml.snakeyaml.DumperOptions;
import org.yaml.snakeyaml.LoaderOptions;
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.constructor.SafeConstructor;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Gives global Cerbos modules a bundle-local identity at render time.
 *
 * <p>Resource policies are version-keyed, but derived-role and exported-variable modules are keyed only
 * by name. Leaving a promoted {@code b_*} policy importing the shared base name means that editing that
 * shared module can change an already-active bundle without changing its id. Rendering both the module
 * name and every import as {@code original__b_<sha>} makes the dependency immutable and allows multiple
 * promoted bundles to coexist in the PDP without duplicate module identities.
 */
final class BundleModuleVersioner {

    private BundleModuleVersioner() { }

    static List<BundleFile> render(List<BundleFile> files, String bundleId) {
        List<ParsedFile> parsed = new ArrayList<>(files.size());
        Map<String, String> derivedNames = new LinkedHashMap<>();
        Map<String, String> variableNames = new LinkedHashMap<>();

        for (BundleFile file : files) {
            String stamped = file.yaml().replace(BundleCanonicalizer.BUNDLE_VERSION_SENTINEL, bundleId);
            Map<String, Object> document = parse(file.path(), stamped);
            parsed.add(new ParsedFile(file.path(), stamped, document));
            collectModuleName(document.get("derivedRoles"), bundleId, derivedNames);
            collectModuleName(document.get("exportVariables"), bundleId, variableNames);
        }

        List<BundleFile> rendered = new ArrayList<>(files.size());
        for (ParsedFile file : parsed) {
            boolean changed = false;
            changed |= rewriteModuleName(file.document().get("derivedRoles"), derivedNames);
            changed |= rewriteModuleName(file.document().get("exportVariables"), variableNames);
            changed |= rewriteImports(file.document(), derivedNames, variableNames);
            rendered.add(new BundleFile(file.path(), changed ? dump(file.document()) : file.stampedYaml()));
        }
        return List.copyOf(rendered);
    }

    private static void collectModuleName(Object rawModule, String bundleId, Map<String, String> names) {
        Map<String, Object> module = map(rawModule);
        if (module == null) return;
        String name = scalar(module.get("name"));
        if (!name.isBlank()) {
            names.put(name, name + "__" + bundleId);
        }
    }

    private static boolean rewriteModuleName(Object rawModule, Map<String, String> names) {
        Map<String, Object> module = map(rawModule);
        if (module == null) return false;
        String oldName = scalar(module.get("name"));
        String newName = names.get(oldName);
        if (newName == null) return false;
        module.put("name", newName);
        return true;
    }

    /** Rewrites imports wherever Cerbos permits them, including resource policies and module documents. */
    private static boolean rewriteImports(Object node, Map<String, String> derivedNames,
                                          Map<String, String> variableNames) {
        if (node instanceof Map<?, ?> rawMap) {
            @SuppressWarnings("unchecked")
            Map<Object, Object> values = (Map<Object, Object>) rawMap;
            boolean changed = rewriteStringList(values.get("importDerivedRoles"), derivedNames);
            Object variables = values.get("variables");
            if (variables instanceof Map<?, ?> variableMap) {
                changed |= rewriteStringList(variableMap.get("import"), variableNames);
            }
            for (Object value : values.values()) {
                changed |= rewriteImports(value, derivedNames, variableNames);
            }
            return changed;
        }
        if (node instanceof List<?> list) {
            boolean changed = false;
            for (Object value : list) {
                changed |= rewriteImports(value, derivedNames, variableNames);
            }
            return changed;
        }
        return false;
    }

    private static boolean rewriteStringList(Object rawList, Map<String, String> names) {
        if (!(rawList instanceof List<?> list) || names.isEmpty()) return false;
        @SuppressWarnings("unchecked")
        List<Object> mutable = (List<Object>) list;
        boolean changed = false;
        for (int i = 0; i < mutable.size(); i++) {
            String replacement = names.get(scalar(mutable.get(i)));
            if (replacement != null) {
                mutable.set(i, replacement);
                changed = true;
            }
        }
        return changed;
    }

    private static Map<String, Object> parse(String path, String yaml) {
        try {
            LoaderOptions options = new LoaderOptions();
            options.setAllowDuplicateKeys(false);
            options.setMaxAliasesForCollections(50);
            Object loaded = new Yaml(new SafeConstructor(options)).load(yaml);
            Map<String, Object> document = map(loaded);
            if (document == null) {
                throw new IllegalStateException("policy document is not a YAML mapping");
            }
            return document;
        } catch (RuntimeException e) {
            throw new IllegalStateException("cannot render policy bundle file '" + path
                    + "' for immutable module publication", e);
        }
    }

    private static String dump(Map<String, Object> document) {
        DumperOptions options = new DumperOptions();
        options.setDefaultFlowStyle(DumperOptions.FlowStyle.BLOCK);
        options.setPrettyFlow(true);
        options.setIndent(2);
        options.setIndicatorIndent(0);
        options.setWidth(160);
        return new Yaml(options).dump(document);
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> map(Object value) {
        return value instanceof Map<?, ?> m ? (Map<String, Object>) m : null;
    }

    private static String scalar(Object value) {
        return value == null ? "" : String.valueOf(value).trim();
    }

    private record ParsedFile(String path, String stampedYaml, Map<String, Object> document) { }
}
