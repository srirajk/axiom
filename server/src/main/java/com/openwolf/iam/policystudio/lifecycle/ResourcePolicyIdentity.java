package com.openwolf.iam.policystudio.lifecycle;

import org.yaml.snakeyaml.LoaderOptions;
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.constructor.SafeConstructor;

import java.util.Map;
import java.util.Optional;

/**
 * Cerbos' semantic identity for a resource policy. File names are deployment details: Cerbos rejects two
 * policies with the same {@code resource + scope + version}, even when their paths differ. The version is
 * deliberately part of this identity so replacement code can never delete a separately deployed policy
 * version. {@link PolicyBundle} separately requires every stored resource policy to use its version
 * sentinel, which yields exactly one version when the bundle is rendered.
 */
public record ResourcePolicyIdentity(String resource, String scope, String version) {

    public ResourcePolicyIdentity {
        resource = resource == null ? "" : resource.trim();
        scope = scope == null ? "" : scope.trim();
        version = version == null ? "" : version.trim();
        if (resource.isBlank()) {
            throw new IllegalArgumentException("resource policy identity requires a resource");
        }
        if (version.isBlank()) {
            throw new IllegalArgumentException("resource policy identity requires a version");
        }
    }

    /**
     * Returns empty only for a valid derived-roles/exported-variables module. Malformed YAML, unknown
     * documents, and malformed resource-policy/module shapes throw, so bundle identity checks fail closed.
     */
    public static Optional<ResourcePolicyIdentity> fromYaml(String yaml) {
        final Object loaded;
        try {
            LoaderOptions options = new LoaderOptions();
            options.setAllowDuplicateKeys(false);
            options.setMaxAliasesForCollections(0);
            loaded = new Yaml(new SafeConstructor(options)).load(yaml);
        } catch (RuntimeException malformed) {
            throw new IllegalArgumentException("malformed YAML in policy bundle file", malformed);
        }
        if (!(loaded instanceof Map<?, ?> doc)) {
            throw new IllegalArgumentException("policy bundle YAML must be a mapping document");
        }
        if (doc.containsKey("resourcePolicy")) {
            if (!(doc.get("resourcePolicy") instanceof Map<?, ?> policy)) {
                throw new IllegalArgumentException("resourcePolicy must be a mapping");
            }
            String resource = scalar(policy.get("resource"));
            String version = scalar(policy.get("version"));
            if (resource.isBlank()) {
                throw new IllegalArgumentException("resourcePolicy.resource must be set");
            }
            if (version.isBlank()) {
                throw new IllegalArgumentException("resourcePolicy.version must be set");
            }
            return Optional.of(new ResourcePolicyIdentity(
                    resource, scalar(policy.get("scope")), version));
        }
        if (validNamedModule(doc.get("derivedRoles")) || validNamedModule(doc.get("exportVariables"))) {
            return Optional.empty();
        }
        throw new IllegalArgumentException(
                "policy bundle YAML must contain a resourcePolicy or a named derivedRoles/exportVariables module");
    }

    /** True for an exact tenant scope or any descendant team/application scope. */
    public boolean belongsToTenant(String tenantId) {
        return scope.equals(tenantId) || scope.startsWith(tenantId + ".");
    }

    /**
     * Put a file into an assembled bundle, replacing any existing resource policy with the same semantic
     * identity. Modules/non-policy files have no identity and are merged by path.
     */
    public static void putReplacing(Map<String, BundleFile> files, BundleFile replacement) {
        Optional<ResourcePolicyIdentity> identity = fromYaml(replacement.yaml());
        BundleFile pathCollision = files.get(replacement.path());
        if (pathCollision != null) {
            Optional<ResourcePolicyIdentity> existingIdentity = fromYaml(pathCollision.yaml());
            boolean samePolicyIdentity = identity.isPresent() && identity.equals(existingIdentity);
            boolean identicalModule = identity.isEmpty() && existingIdentity.isEmpty()
                    && pathCollision.yaml().equals(replacement.yaml());
            if (!samePolicyIdentity && !identicalModule) {
                throw new IllegalArgumentException("bundle path collision at '" + replacement.path()
                        + "' attempts to replace a different policy identity or module");
            }
        }
        if (identity.isPresent()) {
            files.entrySet().removeIf(entry -> fromYaml(entry.getValue().yaml())
                    .map(identity.get()::equals)
                    .orElse(false));
        }
        files.put(replacement.path(), replacement);
    }

    private static String scalar(Object value) {
        return value == null ? "" : String.valueOf(value).trim();
    }

    private static boolean validNamedModule(Object value) {
        return value instanceof Map<?, ?> module && !scalar(module.get("name")).isBlank();
    }
}
