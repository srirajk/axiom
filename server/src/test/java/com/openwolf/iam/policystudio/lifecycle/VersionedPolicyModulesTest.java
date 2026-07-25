package com.openwolf.iam.policystudio.lifecycle;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.yaml.snakeyaml.Yaml;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class VersionedPolicyModulesTest {

    private static final String SENTINEL = BundleCanonicalizer.BUNDLE_VERSION_SENTINEL;

    @Test
    void moduleMutationCreatesANewIdentityWithoutChangingTheOldActiveDependency(@TempDir Path runtime) throws Exception {
        PolicyBundle first = bundle("P.attr.tenant_id == R.attr.tenant_id");
        PolicyBundle mutated = bundle("false");

        assertThat(mutated.bundleId()).isNotEqualTo(first.bundleId());

        List<BundleFile> firstRendered = first.renderedFiles();
        List<BundleFile> mutatedRendered = mutated.renderedFiles();
        String firstName = moduleName(firstRendered);
        String mutatedName = moduleName(mutatedRendered);

        assertThat(firstName).isEqualTo("tenant_roles__" + first.bundleId());
        assertThat(mutatedName).isEqualTo("tenant_roles__" + mutated.bundleId());
        assertThat(mutatedName).isNotEqualTo(firstName);
        assertThat(importedName(firstRendered)).isEqualTo(firstName);
        assertThat(importedName(mutatedRendered)).isEqualTo(mutatedName);

        PromotedBundleLoader loader = new PromotedBundleLoader(runtime.toString(), 0L, 1);
        List<Path> firstWritten = loader.load(first);
        loader.load(mutated);

        assertThat(firstWritten.getFirst().getFileName().toString())
                .as("the module must be published before the resource policy that imports it")
                .contains("tenant_roles");

        try (var paths = Files.list(runtime)) {
            assertThat(paths.map(p -> p.getFileName().toString()).toList())
                    .anyMatch(name -> name.contains(first.bundleId()) && name.contains("tenant_roles"))
                    .anyMatch(name -> name.contains(mutated.bundleId()) && name.contains("tenant_roles"));
        }

        // The old active policy remains bound to its original immutable module even after the changed
        // module is published alongside it; no shared name can silently redirect the old decision.
        assertThat(importedName(first.renderedFiles())).isEqualTo(firstName);
        assertThat(moduleBody(first.renderedFiles())).contains("P.attr.tenant_id == R.attr.tenant_id");
        assertThat(moduleBody(mutated.renderedFiles())).contains("false");
    }

    @Test
    void exportedVariableNamesAndImportsAreVersionedToo() {
        String variable = """
                apiVersion: api.cerbos.dev/v1
                exportVariables:
                  name: shared_values
                  definitions:
                    enabled: "true"
                """;
        String resource = """
                apiVersion: api.cerbos.dev/v1
                resourcePolicy:
                  version: "%s"
                  resource: report
                  scope: ""
                  variables:
                    import: [shared_values]
                  rules:
                    - actions: [read]
                      effect: EFFECT_ALLOW
                      roles: [reader]
                """.formatted(SENTINEL);
        PolicyBundle bundle = PolicyBundle.materialize("acme", List.of(
                        new BundleFile("policies/shared_values.yaml", variable),
                        new BundleFile("policies/report.yaml", resource)),
                List.of(), metadata(), new BundleCanonicalizer());

        List<BundleFile> rendered = bundle.renderedFiles();
        String expected = "shared_values__" + bundle.bundleId();
        assertThat(exportedVariableName(rendered)).isEqualTo(expected);
        assertThat(importedVariableName(rendered)).isEqualTo(expected);
    }

    private static PolicyBundle bundle(String condition) {
        String module = """
                apiVersion: api.cerbos.dev/v1
                derivedRoles:
                  name: tenant_roles
                  definitions:
                    - name: same_tenant
                      parentRoles: [reader]
                      condition:
                        match:
                          expr: "%s"
                """.formatted(condition);
        String root = """
                apiVersion: api.cerbos.dev/v1
                resourcePolicy:
                  version: "%s"
                  resource: report
                  scope: ""
                  importDerivedRoles: [tenant_roles]
                  rules:
                    - actions: [read]
                      effect: EFFECT_ALLOW
                      derivedRoles: [same_tenant]
                """.formatted(SENTINEL);
        return PolicyBundle.materialize("acme", List.of(
                        new BundleFile("policies/tenant_roles.yaml", module),
                        new BundleFile("policies/report.yaml", root)),
                List.of(), metadata(), new BundleCanonicalizer());
    }

    private static BundleTestMetadata metadata() {
        return new BundleTestMetadata("fixture", 1, "oracle", "cerbos:0.53.0");
    }

    private static String moduleName(List<BundleFile> files) {
        return scalar(moduleDocument(files).get("derivedRoles"), "name");
    }

    private static String exportedVariableName(List<BundleFile> files) {
        return scalar(document(files, "shared_values").get("exportVariables"), "name");
    }

    private static String importedName(List<BundleFile> files) {
        Map<String, Object> resource = map(document(files, "report").get("resourcePolicy"));
        return String.valueOf(((List<?>) resource.get("importDerivedRoles")).getFirst());
    }

    private static String importedVariableName(List<BundleFile> files) {
        Map<String, Object> resource = map(document(files, "report").get("resourcePolicy"));
        Map<String, Object> variables = map(resource.get("variables"));
        return String.valueOf(((List<?>) variables.get("import")).getFirst());
    }

    private static String moduleBody(List<BundleFile> files) {
        return files.stream().filter(f -> f.path().contains("tenant_roles")).findFirst().orElseThrow().yaml();
    }

    private static Map<String, Object> moduleDocument(List<BundleFile> files) {
        return document(files, "tenant_roles");
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> document(List<BundleFile> files, String pathPart) {
        String yaml = files.stream().filter(f -> f.path().contains(pathPart)).findFirst().orElseThrow().yaml();
        return (Map<String, Object>) new Yaml().load(yaml);
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> map(Object value) {
        return (Map<String, Object>) value;
    }

    private static String scalar(Object map, String key) {
        return String.valueOf(VersionedPolicyModulesTest.map(map).get(key));
    }
}
