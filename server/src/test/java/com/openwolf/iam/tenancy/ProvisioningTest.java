package com.openwolf.iam.tenancy;

import com.openwolf.iam.policystudio.BaseBundleGrounding;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.yaml.snakeyaml.Yaml;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Axiom B4.2 — a freshly provisioned tenant uses the EXACT B1 deny-all bootstrap posture and DENIES
 * every enumerated base-ceiling tuple, until a reviewed total restriction policy is promoted. Nothing
 * falls through the parental-consent inheritance.
 */
class ProvisioningTest {

    private static final String TENANT = "acme";
    private static final String PARENTAL_CONSENT = "SCOPE_PERMISSIONS_REQUIRE_PARENTAL_CONSENT_FOR_ALLOWS";

    @Test
    void relativeStagingUsesTheUacRootForThePlatformPolicyPackage() {
        Path base = ProvisioningTestSupport.baseBundleDir();

        assertThat(CerbosPolicyBootstrapAdapter.relativeStagingRoot(base, "build/policy-staging"))
                .isEqualTo(base.getParent().getParent().resolve("build/policy-staging").normalize());
    }

    @Test
    @SuppressWarnings("unchecked")
    void freshTenantBootstrapDeniesEverything(@TempDir Path staging) throws IOException {
        CerbosPolicyBootstrapAdapter policy = ProvisioningTestSupport.realPolicyAdapter(staging);
        TenantBootstrapBundle bundle = policy.stage(TENANT);

        assertThat(bundle.childByResource()).isNotEmpty();
        assertThat(bundle.childByResource()).hasSize(4);
        assertThat(bundle.policyVersion()).startsWith("b_");
        assertThat(bundle.policyBundle().bundleId()).isEqualTo(bundle.policyVersion());
        assertThat(bundle.policyBundle().renderedFiles())
                .allMatch(file -> !file.yaml().contains("__BUNDLE_VERSION__"));
        assertThat(bundle.policyBundle().renderedFiles().stream()
                .filter(file -> file.yaml().contains("resourcePolicy:")))
                .allMatch(file -> file.yaml().contains(bundle.policyVersion()));

        Yaml yaml = new Yaml();
        for (Map.Entry<String, String> child : bundle.childByResource().entrySet()) {
            String resource = child.getKey();
            Map<String, Object> doc = yaml.load(child.getValue());
            Map<String, Object> rp = (Map<String, Object>) doc.get("resourcePolicy");

            // EXACT B1 posture: scope = tenant id, parental-consent, non-empty rules (never an empty policy).
            assertThat(rp.get("scope")).as("scope must be the tenant id").isEqualTo(TENANT);
            assertThat(rp.get("scopePermissions")).as("must use the B1 parental-consent posture")
                    .isEqualTo(PARENTAL_CONSENT);
            List<Map<String, Object>> rules = (List<Map<String, Object>>) rp.get("rules");
            assertThat(rules).as("a deny-all child is never empty (empty = fail-open)").isNotEmpty();

            // Every rule is EFFECT_DENY — the fresh tenant grants NOTHING.
            for (Map<String, Object> rule : rules) {
                assertThat(rule.get("effect")).as("every fresh-tenant rule must DENY").isEqualTo("EFFECT_DENY");
            }

            // The deny-all covers EXACTLY the base ceiling's enumerated (action, role) tuples — no gap,
            // so no tuple can fall through to the parent ALLOW.
            Set<String> denied = tuples(rules);
            Set<String> ceiling = ceilingTuples(resource);
            assertThat(denied).as("deny-all must cover every enumerated base tuple for '%s'", resource)
                    .isEqualTo(ceiling);
        }
        // The live Cerbos compile of the staged bundle is captured as B4.2 evidence out of band (it
        // needs the pinned image and an ephemeral docker run); the deterministic deny-all totality
        // above is the hermetic proof that the fresh tenant denies every enumerated base tuple.
    }

    @Test
    void provisionActivatesWithTheContentAddressedBootstrapVersion(@TempDir Path staging) {
        ActiveTenantDirectory directory = new ActiveTenantDirectory(ProvisioningTestSupport.activeRepo());
        TenantProvisioningService service = new TenantProvisioningService(
                ProvisioningTestSupport.opsRepo(), directory,
                ProvisioningTestSupport.realPolicyAdapterNoProbe(staging),
                new InProcessTenantNamespaceAdapter(),
                new PersistentAuditPartitionAdapter(ProvisioningTestSupport.auditRepo()),
                ProvisioningTestSupport.acceptingPublisher(), ProvisioningTestSupport.tenantRepo());

        ProvisioningResult result = service.provision(
                new ProvisioningRequest(TENANT, "Acme", "acme"), "key-fresh-1", "admin");

        assertThat(result.isActive()).isTrue();
        assertThat(result.policyVersion()).startsWith("b_");
        assertThat(directory.find(TENANT)).contains(result.policyVersion());
    }

    // ── helpers ────────────────────────────────────────────────────────────────────────────────

    @SuppressWarnings("unchecked")
    private static Set<String> tuples(List<Map<String, Object>> rules) {
        Set<String> out = new LinkedHashSet<>();
        for (Map<String, Object> rule : rules) {
            for (Object action : (List<Object>) rule.get("actions")) {
                for (Object role : (List<Object>) rule.get("roles")) {
                    out.add(action + "@" + role);
                }
            }
        }
        return out;
    }

    private static Set<String> ceilingTuples(String resource) {
        return BaseBundleGrounding.read(ProvisioningTestSupport.baseBundleDir(), resource)
                .ceiling().tuples().stream()
                .map(t -> t.action() + "@" + t.role())
                .collect(java.util.stream.Collectors.toSet());
    }
}
