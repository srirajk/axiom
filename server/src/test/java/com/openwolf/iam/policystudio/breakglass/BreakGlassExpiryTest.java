package com.openwolf.iam.policystudio.breakglass;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.openwolf.iam.policystudio.BaseCeiling;
import com.openwolf.iam.policystudio.CanonicalPolicyWriter;
import com.openwolf.iam.policystudio.PolicyIR;
import com.openwolf.iam.policystudio.TenantScope;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;
import org.testcontainers.containers.BindMode;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.utility.DockerImageName;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * C6.1 — THE HEADLINE: a break-glass grant EXPIRES WITH THE CONTROL PLANE DOWN.
 *
 * <p>The break-glass artifact carries the expiry AS A CEL TIME CONDITION inside the ALLOW
 * ({@code now() < timestamp(expiresAt)}), paired with a complementary DENY ({@code now() >= …}) so
 * expiry fails CLOSED even under {@code REQUIRE_PARENTAL_CONSENT_FOR_ALLOWS}. This test compiles that
 * exact artifact and drives a REAL {@code CheckResources} against an EPHEMERAL Cerbos PDP —
 * Testcontainers, a DISTINCT random container name + host port, NEVER the demo's
 * {@code conduit-cerbos:3594}. There is NO studio, NO IAM app context, NO control plane in this test:
 * the only thing running is the PDP. Yet:
 *
 * <ul>
 *   <li>a grant whose baked {@code expiresAt} is already in the PAST ⇒ <b>DENY</b> (self-limited);</li>
 *   <li>a fresh grant ⇒ <b>ALLOW</b>;</li>
 *   <li>and (visceral) a single grant with a short window flips ALLOW→DENY as wall-clock time crosses
 *       {@code expiresAt} — same artifact, PDP alone, nothing revoked externally.</li>
 * </ul>
 *
 * If expiry depended on any external revocation (a cron, the studio, a control-plane call) this test
 * would be RED — the control plane is not running.
 */
class BreakGlassExpiryTest {

    // Pinned to 0.53.0 — the exact version the runtime Cerbos PDP + the provisioning gate run
    // (ProvisioningTestSupport, cerbos-policy-gate). An unpinned :latest could silently drift the
    // CEL semantics this expiry proof depends on. Overridable via CERBOS_IMAGE for local pins.
    private static final DockerImageName CERBOS_IMAGE = DockerImageName.parse(
            System.getenv().getOrDefault("CERBOS_IMAGE", "ghcr.io/cerbos/cerbos:0.53.0"));
    private static final ObjectMapper JSON = new ObjectMapper();

    private final BreakGlassPolicyCompiler compiler = new BreakGlassPolicyCompiler();
    private final CanonicalPolicyWriter writer = new CanonicalPolicyWriter();

    /** The minimal parent ceiling (root scope) that grants the emergency tuple — parental consent. */
    private String parentCeiling() {
        return """
                apiVersion: api.cerbos.dev/v1
                resourcePolicy:
                  version: "default"
                  resource: agent
                  scope: ""
                  rules:
                    - actions: ["invoke", "invoke_membership", "register", "deregister"]
                      effect: EFFECT_ALLOW
                      roles: ["platform_admin"]
                """;
    }

    private BaseCeiling ceiling() {
        return BreakGlassFixtures.ceiling();
    }

    /** Compile a break-glass child for {@code scope} whose grant expires at {@code expiresAt}. */
    private String childYaml(String scope, Instant issuedAt, Instant expiresAt) {
        BreakGlassGrant grant = new BreakGlassGrant(
                TenantScope.of(scope), "agent", "register", "platform_admin",
                issuedAt, expiresAt, "emergency incident #4711", "alice");
        PolicyIR ir = compiler.compile(grant, ceiling());
        return writer.write(ir);
    }

    private GenericContainer<?> cerbos(String confDir, String policyDir) {
        return new GenericContainer<>(CERBOS_IMAGE)
                .withExposedPorts(3592)
                .withFileSystemBind(confDir, "/conf", BindMode.READ_ONLY)
                .withFileSystemBind(policyDir, "/policies", BindMode.READ_ONLY)
                .withCommand("server", "--config=/conf/config.yaml")
                .waitingFor(Wait.forHttp("/_cerbos/health").forPort(3592).forStatusCode(200)
                        .withStartupTimeout(Duration.ofSeconds(90)));
    }

    /** One real CheckResources against the PDP; returns the effect for register at {@code scope}. */
    private String decide(String baseUrl, String scope) throws Exception {
        String body = """
                {"principal":{"id":"admin","policyVersion":"default","roles":["platform_admin"],"attr":{}},
                 "resources":[{"actions":["register"],
                  "resource":{"kind":"agent","policyVersion":"default","scope":"%s","id":"a1","attr":{}}}]}
                """.formatted(scope);
        HttpResponse<String> resp = HttpClient.newHttpClient().send(
                HttpRequest.newBuilder()
                        .uri(URI.create(baseUrl + "/api/check/resources"))
                        .header("Content-Type", "application/json")
                        .POST(HttpRequest.BodyPublishers.ofString(body))
                        .build(),
                HttpResponse.BodyHandlers.ofString());
        assertThat(resp.statusCode()).as("check body: %s", resp.body()).isEqualTo(200);
        JsonNode actions = JSON.readTree(resp.body()).path("results").path(0).path("actions");
        return actions.path("register").asText();
    }

    @Test
    void expiresWithControlPlaneDown() throws Exception {
        requireDocker();

        Path work = Files.createTempDirectory("breakglass-c6-");
        Path conf = work.resolve("conf");
        Path policies = work.resolve("policies");
        Files.createDirectories(conf);
        Files.createDirectories(policies);
        Files.writeString(conf.resolve("config.yaml"), """
                server:
                  httpListenAddr: ":3592"
                storage:
                  driver: "disk"
                  disk:
                    directory: /policies
                    watchForChanges: false
                """);

        Instant now = Instant.now();
        // (a) already-expired grant — baked expiresAt in the PAST ⇒ must DENY.
        Instant expiredAt = now.minusSeconds(1).truncatedTo(ChronoUnit.SECONDS);
        // (b) fresh grant — far-future expiry ⇒ must ALLOW for the whole run.
        Instant freshUntil = now.plus(Duration.ofMinutes(30)).truncatedTo(ChronoUnit.SECONDS);
        // (c) live-flip grant — short window that survives container startup, then lapses.
        Instant liveUntil = now.plusSeconds(28).truncatedTo(ChronoUnit.SECONDS);

        String expiredChild = childYaml("acme-expired", now, expiredAt);
        Files.writeString(policies.resolve("agent_root.yaml"), parentCeiling());
        Files.writeString(policies.resolve("bg_expired.yaml"), expiredChild);
        Files.writeString(policies.resolve("bg_fresh.yaml"), childYaml("acme-fresh", now, freshUntil));
        Files.writeString(policies.resolve("bg_live.yaml"), childYaml("acme-live", now, liveUntil));

        StringBuilder runLog = new StringBuilder();
        runLog.append("C6.1 break-glass expiry — PDP ONLY, control plane NOT running.\n")
                .append("cerbos image: ").append(CERBOS_IMAGE).append('\n')
                .append("now=").append(now).append('\n')
                .append("expiredAt=").append(expiredAt).append(" freshUntil=").append(freshUntil)
                .append(" liveUntil=").append(liveUntil).append("\n\n");

        try (GenericContainer<?> pdp = cerbos(conf.toString(), policies.toString())) {
            pdp.start();
            String base = "http://" + pdp.getHost() + ":" + pdp.getMappedPort(3592);
            runLog.append("PDP up at ").append(base)
                    .append(" (container '").append(pdp.getContainerName())
                    .append("', NOT conduit-cerbos:3594)\n\n");

            // ── (a) HEADLINE: the already-expired grant DENIES, PDP alone. ──
            String expired = decide(base, "acme-expired");
            runLog.append("[expired grant] register @ acme-expired -> ").append(expired).append('\n');
            assertThat(expired).as("an expired break-glass grant must DENY inside the PDP").isEqualTo("EFFECT_DENY");

            // ── (b) a fresh grant ALLOWS. ──
            String fresh = decide(base, "acme-fresh");
            runLog.append("[fresh grant]   register @ acme-fresh   -> ").append(fresh).append('\n');
            assertThat(fresh).as("a fresh break-glass grant must ALLOW").isEqualTo("EFFECT_ALLOW");

            // ── (c) VISCERAL: the SAME live grant flips ALLOW->DENY as wall-clock crosses expiry. ──
            long secsLeft = Duration.between(Instant.now(), liveUntil).toSeconds();
            if (secsLeft >= 3) {
                String liveBefore = decide(base, "acme-live");
                runLog.append("[live grant]    register @ acme-live (before expiry, ")
                        .append(secsLeft).append("s left) -> ").append(liveBefore).append('\n');
                assertThat(liveBefore).isEqualTo("EFFECT_ALLOW");
            } else {
                runLog.append("[live grant]    startup consumed the pre-expiry window — before-check skipped\n");
            }
            // Wait until strictly past expiry, then re-check the SAME artifact.
            long waitMs = Duration.between(Instant.now(), liveUntil).toMillis() + 1500;
            if (waitMs > 0) {
                Thread.sleep(waitMs);
            }
            String liveAfter = decide(base, "acme-live");
            runLog.append("[live grant]    register @ acme-live (after expiry)  -> ").append(liveAfter).append('\n');
            assertThat(liveAfter).as("the SAME grant must DENY once wall-clock passes expiry — PDP alone")
                    .isEqualTo("EFFECT_DENY");

            runLog.append("\nRESULT: expiry is enforced by the CEL time condition IN the artifact, ")
                    .append("evaluated by the PDP on every CheckResources. No control plane was involved.\n");
        }

        writeEvidence(expiredChild, childYaml("acme-live", now, liveUntil), runLog.toString());
    }

    private void writeEvidence(String expiredChildYaml, String liveChildYaml, String runLog) {
        try {
            Path repoRoot = Path.of(System.getProperty("user.dir")).getParent(); // module cwd is iam-service/
            Path dir = repoRoot.resolve("docs/implementation/evidence/studio/c6");
            if (!Files.isDirectory(dir.getParent().getParent())) {
                return; // evidence tree absent in this checkout
            }
            Files.createDirectories(dir);
            Files.writeString(dir.resolve("break-glass-policy-expired.yaml"), expiredChildYaml);
            Files.writeString(dir.resolve("break-glass-policy-live.yaml"), liveChildYaml);
            Files.writeString(dir.resolve("expiry-run-controlplane-down.log"), runLog);
        } catch (Exception ignored) {
            // evidence writing is best-effort; the assertions above are the proof
        }
    }

    private static boolean dockerAvailable() {
        try {
            Process p = new ProcessBuilder("docker", "--version").redirectErrorStream(true).start();
            return p.waitFor() == 0;
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Docker gate (H7). Locally — for a dev without Docker — a missing daemon is an assume-skip so
     * the unit suite still runs. In CI, where Docker is guaranteed present, the workflow sets
     * {@code CONDUIT_DOCKER_REQUIRED=true}, which turns the skip into a HARD FAILURE: a
     * silently-skipped security proof must NOT pass the gate green.
     */
    private static void requireDocker() {
        boolean docker = dockerAvailable();
        boolean requiredInCi = Boolean.parseBoolean(
                System.getenv().getOrDefault("CONDUIT_DOCKER_REQUIRED", "false"));
        if (requiredInCi) {
            assertThat(docker)
                    .as("CONDUIT_DOCKER_REQUIRED=true (CI) but Docker is unavailable — this "
                            + "live-PDP security proof must RUN, not skip green")
                    .isTrue();
        } else {
            Assumptions.assumeTrue(docker, "Docker not available — skipping the live-PDP headline");
        }
    }
}
