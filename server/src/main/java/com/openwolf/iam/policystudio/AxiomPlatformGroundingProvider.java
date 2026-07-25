package com.openwolf.iam.policystudio;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.openwolf.iam.policystudio.lifecycle.BundleCanonicalizer;
import com.openwolf.iam.policystudio.lifecycle.BundleContentReader;
import com.openwolf.iam.policystudio.lifecycle.PolicyBundleRecord;
import com.openwolf.iam.policystudio.lifecycle.PolicyBundleRepository;
import com.openwolf.iam.tenancy.ActiveTenantDirectory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

/**
 * AXM-108 grounding provider for Axiom's platform policy studio.
 *
 * <p>It consumes only the versioned Axiom platform-contract document and the isolated Axiom
 * platform-policy package. It never reads an external inventory, relationship, or governance-policy
 * input.
 */
@Component
public final class AxiomPlatformGroundingProvider implements StudioGroundingProvider {

    private final ObjectMapper objectMapper;
    private final CanonicalPolicyWriter writer;
    private final PolicyYamlParser parser;
    private final ActiveTenantDirectory directory;
    private final PolicyBundleRepository bundles;
    private final Path contractPath;
    private final Path policyDir;

    public AxiomPlatformGroundingProvider(
            ObjectMapper objectMapper,
            CanonicalPolicyWriter writer,
            PolicyYamlParser parser,
            ActiveTenantDirectory directory,
            PolicyBundleRepository bundles,
            @Value("${iam.policy-studio.platform-contract-path:/app/platform-contract/axiom-platform-contract.json}")
            String contractPath,
            @Value("${iam.policy-studio.base-bundle-dir:/app/platform-policy/policies}") String policyDir) {
        this.objectMapper = objectMapper;
        this.writer = writer;
        this.parser = parser;
        this.directory = directory;
        this.bundles = bundles;
        this.contractPath = Path.of(contractPath);
        this.policyDir = Path.of(policyDir);
    }

    @Override
    public StudioGroundingSnapshot snapshot(String tenantId, String resourceKind) {
        if (tenantId == null || tenantId.isBlank()) throw new IllegalArgumentException("tenantId must be set");
        Contract contract = readContract();
        PlatformResourceKind.require(resourceKind);
        if (!contract.resourceKind().equals(PlatformResourceKind.IAM_RESOURCE)) {
            throw new IllegalStateException("platform contract resource kind is not iam-resource");
        }
        BaseBundleGrounding.Facts base = BaseBundleGrounding.read(policyDir, resourceKind);
        ManifestVocabulary vocabulary = new ManifestVocabulary(
                resourceKind, base.actions(), contract.classifications(), contract.attributes(),
                base.roles(), base.approvedImports());
        BaseCeiling ceiling = base.ceiling();
        return new StudioGroundingSnapshot(
                tenantId,
                vocabulary,
                ceiling,
                matrixFor(tenantId, ceiling),
                currentBundle(tenantId, ceiling),
                List.of(contractPath.getFileName() + "#sha256=" + contract.sha256()));
    }

    private Contract readContract() {
        try {
            if (!Files.isRegularFile(contractPath)) {
                throw new IllegalStateException("Axiom platform contract is missing");
            }
            byte[] bytes = Files.readAllBytes(contractPath);
            JsonNode root = objectMapper.readTree(bytes);
            String version = text(root, "schema_version");
            String resourceKind = text(root, "resource_kind");
            if (!"axiom-platform-contract.v1".equals(version) || resourceKind.isBlank()) {
                throw new IllegalStateException("invalid Axiom platform contract");
            }
            return new Contract(resourceKind, stringSet(root, "classifications"),
                    stringSet(root, "attributes"), sha256(bytes));
        } catch (Exception exception) {
            if (exception instanceof IllegalStateException state) throw state;
            throw new IllegalStateException("unable to read Axiom platform contract", exception);
        }
    }

    private static String text(JsonNode root, String field) {
        JsonNode value = root.path(field);
        return value.isTextual() ? value.asText() : "";
    }

    private static Set<String> stringSet(JsonNode root, String field) {
        JsonNode values = root.path(field);
        if (!values.isArray()) throw new IllegalStateException("invalid Axiom platform contract field " + field);
        java.util.TreeSet<String> result = new java.util.TreeSet<>();
        values.forEach(value -> {
            if (!value.isTextual() || value.asText().isBlank()) {
                throw new IllegalStateException("invalid Axiom platform contract value");
            }
            result.add(value.asText());
        });
        return Set.copyOf(result);
    }

    private static String sha256(byte[] bytes) {
        try {
            return java.util.HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));
        } catch (Exception exception) {
            throw new IllegalStateException("SHA-256 unavailable", exception);
        }
    }

    private static ConsequenceFixtureMatrix matrixFor(String tenantId, BaseCeiling ceiling) {
        List<FixtureCell> cells = new ArrayList<>();
        ceiling.tuples().stream()
                .sorted((left, right) -> (left.role() + ':' + left.action())
                        .compareTo(right.role() + ':' + right.action()))
                .forEach(tuple -> {
                    String label = tuple.role() + '-' + tuple.action();
                    cells.add(new FixtureCell(Set.of(tuple.role()), tenantId, Map.of(), tenantId,
                            Map.of("resource_type", "platform"), tuple.action(), label + "-same-tenant"));
                    cells.add(new FixtureCell(Set.of(tuple.role()), tenantId, Map.of(), tenantId + "-other",
                            Map.of("resource_type", "platform"), tuple.action(), label + "-cross-tenant"));
                });
        return ConsequenceFixtureMatrix.of(cells);
    }

    private BundleSnapshot currentBundle(String tenantId, BaseCeiling ceiling) {
        Optional<String> activeVersion = directory.find(tenantId);
        if (activeVersion.isPresent()) {
            Optional<PolicyBundleRecord> record = bundles.findById(activeVersion.get());
            if (record.isPresent()) {
                Optional<String> child = BundleContentReader.tenantChildYaml(
                        record.get().getCanonicalContent(), ceiling.resourceKind(), record.get().getTenantId());
                if (child.isPresent()) {
                    PolicyIR policy = parser.parse(child.get().replace(BundleCanonicalizer.BUNDLE_VERSION_SENTINEL, "default"));
                    return new BundleSnapshot(activeVersion.get(), policy, ceiling, record.get().getCanonicalContent());
                }
                return new BundleSnapshot(activeVersion.get(), null, ceiling, record.get().getCanonicalContent());
            }
        }
        return BundleSnapshot.of(null, ceiling, writer);
    }

    private record Contract(String resourceKind, Set<String> classifications, Set<String> attributes, String sha256) { }
}
