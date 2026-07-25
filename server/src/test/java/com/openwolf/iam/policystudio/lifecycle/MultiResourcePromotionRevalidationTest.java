package com.openwolf.iam.policystudio.lifecycle;

import com.openwolf.iam.policystudio.BaseCeiling;
import com.openwolf.iam.policystudio.ConsequenceApprovalRecord;
import com.openwolf.iam.policystudio.ConsequenceReview;
import com.openwolf.iam.policystudio.GeneratedPolicyValidator;
import com.openwolf.iam.policystudio.ManifestVocabulary;
import com.openwolf.iam.policystudio.PolicyYamlParser;
import com.openwolf.iam.policystudio.StudioGroundingProvider;
import com.openwolf.iam.policystudio.StudioGroundingSnapshot;
import com.openwolf.iam.tenancy.ActiveTenantDirectory;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

/** Promotion re-validates every tenant child against grounding for that child's resource kind. */
class MultiResourcePromotionRevalidationTest {

    @Test
    void agentThenRelationshipPromotionUsesBothResourceCeilings(@TempDir Path runtimePolicies) {
        List<String> groundingLookups = new ArrayList<>();
        StudioGroundingProvider grounding = (tenantId, resourceKind) -> {
            groundingLookups.add(resourceKind);
            return switch (resourceKind) {
                case "agent" -> snapshot(tenantId, C5LifecycleFixtures.vocab(),
                        C5LifecycleFixtures.agentCeiling());
                case "relationship" -> snapshot(tenantId, relationshipVocabulary(), relationshipCeiling());
                default -> throw new IllegalStateException("unexpected grounding kind " + resourceKind);
            };
        };
        PromotionValidationContextProvider contexts =
                new ManifestPromotionValidationContextProvider(grounding);

        ActiveTenantDirectory directory = C5LifecycleFixtures.directory();
        PolicyBundle baseline = C5LifecycleFixtures.bundle(
                C5LifecycleFixtures.candidateBody(), C5LifecycleFixtures.matrixHash());
        directory.activate(C5LifecycleFixtures.TENANT, baseline.bundleId());

        PolicyPromotionService promotion = new PolicyPromotionService(
                directory,
                C5LifecycleFixtures.approvalService(),
                C5LifecycleFixtures.promotionRepo(),
                C5LifecycleFixtures.bundleRepo(),
                C5LifecycleFixtures.approvalRepo(),
                C5LifecycleFixtures.canon(),
                C5LifecycleFixtures.gitResolver("cross-kind-test"),
                C5LifecycleFixtures.passingProbe(),
                new GeneratedPolicyValidator(),
                new PolicyYamlParser(),
                contexts,
                new PromotedBundleLoader(runtimePolicies.toString(), 0L, 1));

        // First promotion edits only the agent child.
        PolicyBundle agentBundle = C5LifecycleFixtures.bundle(
                C5LifecycleFixtures.currentBody(), C5LifecycleFixtures.matrixHash());
        promote(promotion, baseline, agentBundle, "agent-promotion");
        assertThat(directory.find(C5LifecycleFixtures.TENANT)).hasValue(agentBundle.bundleId());
        assertThat(groundingLookups).containsExactly("agent");

        // The next tenant-wide snapshot carries the previously promoted agent child and adds a valid
        // relationship child. Both must be re-validated against their own trusted ceilings.
        groundingLookups.clear();
        List<BundleFile> files = new ArrayList<>(agentBundle.files());
        files.add(new BundleFile("relationship@acme.yaml",
                C5LifecycleFixtures.toSentinelBody(relationshipBody())));
        PolicyBundle relationshipBundle = PolicyBundle.materialize(
                C5LifecycleFixtures.TENANT,
                files,
                agentBundle.manifestRefs(),
                C5LifecycleFixtures.testMetadata(C5LifecycleFixtures.matrixHash()),
                C5LifecycleFixtures.canon());

        promote(promotion, agentBundle, relationshipBundle, "relationship-promotion");

        assertThat(directory.find(C5LifecycleFixtures.TENANT)).hasValue(relationshipBundle.bundleId());
        assertThat(groundingLookups)
                .as("each tenant child must resolve its own manifest vocabulary and base ceiling")
                .containsExactly("agent", "relationship");
    }

    private static void promote(
            PolicyPromotionService promotion, PolicyBundle current, PolicyBundle candidate, String key) {
        ConsequenceReview review = C5LifecycleFixtures.handReview(current, candidate);
        ConsequenceApprovalRecord approval = C5LifecycleFixtures.approve(review, "security-reviewer");
        promotion.promote(new PromotionRequest(
                candidate, review, approval, key, PromotionRecord.Kind.PROMOTION));
    }

    private static StudioGroundingSnapshot snapshot(
            String tenantId, ManifestVocabulary vocabulary, BaseCeiling ceiling) {
        return new StudioGroundingSnapshot(tenantId, vocabulary, ceiling, null, null, List.of());
    }

    private static ManifestVocabulary relationshipVocabulary() {
        return new ManifestVocabulary(
                "relationship",
                Set.of("read"),
                Set.of(),
                Set.of(),
                Set.of("chat_user", "relationship_manager", "domain_admin", "platform_admin"),
                Set.of("business_derived_roles"));
    }

    private static BaseCeiling relationshipCeiling() {
        return new BaseCeiling(
                "relationship",
                Set.of(
                        new BaseCeiling.Tuple("read", "chat_user"),
                        new BaseCeiling.Tuple("read", "relationship_manager"),
                        new BaseCeiling.Tuple("read", "domain_admin"),
                        new BaseCeiling.Tuple("read", "platform_admin")),
                true,
                Set.of("relationship@", "relationship@default"));
    }

    private static String relationshipBody() {
        return """
                apiVersion: api.cerbos.dev/v1
                resourcePolicy:
                  version: "default"
                  resource: relationship
                  scope: "acme"
                  scopePermissions: SCOPE_PERMISSIONS_REQUIRE_PARENTAL_CONSENT_FOR_ALLOWS
                  rules:
                    - actions: ["read"]
                      effect: EFFECT_ALLOW
                      roles: ["chat_user", "relationship_manager"]
                    - actions: ["read"]
                      effect: EFFECT_ALLOW
                      roles: ["domain_admin"]
                    - actions: ["read"]
                      effect: EFFECT_ALLOW
                      roles: ["platform_admin"]
                """;
    }
}
