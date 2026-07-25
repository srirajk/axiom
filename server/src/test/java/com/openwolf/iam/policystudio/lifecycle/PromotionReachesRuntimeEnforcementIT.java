package com.openwolf.iam.policystudio.lifecycle;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
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
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * S1 — THE HEADLINE: a promotion actually flips a live PDP decision.
 *
 * <p>Before this wire, the Policy Studio was theatre: promotion compiled a candidate and flipped a
 * pointer, but nothing loaded the promoted bundle into the serving PDP, so runtime enforcement never
 * changed. This test proves the fix end to end against a REAL Cerbos with the SAME disk-storage +
 * {@code watchForChanges} config the demo runs — on an EPHEMERAL Testcontainers PDP with a random host
 * port, NEVER the demo's {@code conduit-cerbos:3594}.
 *
 * <ol>
 *   <li>Load the base bundle ({@code version: default}) that DENIES tuple T; assert a real
 *       {@code CheckResources} at {@code policyVersion=default} DENIES.</li>
 *   <li>Run the REAL {@link PromotedBundleLoader} — the production load step — to materialise a promoted
 *       candidate bundle (every policy stamped {@code version=<bundleId>}) that ALLOWS T into the watched
 *       directory; wait for {@code watchForChanges} to reload.</li>
 *   <li>Assert {@code CheckResources} at {@code policyVersion=<bundleId>} now ALLOWS T — the promotion
 *       changed a live PDP decision.</li>
 *   <li>Assert {@code policyVersion=default} STILL DENIES T — the promoted bundle is additive, never
 *       destructive; the default tenant is untouched.</li>
 * </ol>
 *
 * <p>If the load step were still missing (the old theatre), step 3 would be RED: the PDP would have no
 * {@code version=<bundleId>} policy and deny.
 */
class PromotionReachesRuntimeEnforcementIT {

    // Pinned to 0.53.0 — the exact runtime + gate version (config.yaml, cerbos-policy-gate).
    private static final DockerImageName CERBOS_IMAGE = DockerImageName.parse(
            System.getenv().getOrDefault("CERBOS_IMAGE", "ghcr.io/cerbos/cerbos:0.53.0"));
    private static final ObjectMapper JSON = new ObjectMapper();

    /** Tuple T: a relationship_manager invoking the {@code agent} resource. Base denies; the candidate allows. */
    private static final String TUPLE_ROLE = "relationship_manager";
    private static final String TUPLE_ACTION = "invoke";

    /** The base bundle: version "default", root scope, ALLOWs invoke only for platform_admin ⇒ T DENIES. */
    private String baseBundle() {
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

    /**
     * The candidate bundle in the C5 sentinel form ({@code version} carries the reproducible sentinel).
     * It ADDS an ALLOW for the tuple T role. {@link PolicyBundle#renderedFiles()} stamps the concrete
     * content-addressed {@code bundleId} into the version position before the loader writes it.
     */
    private String candidateSentinelBundle() {
        return """
                apiVersion: api.cerbos.dev/v1
                resourcePolicy:
                  version: %s
                  resource: agent
                  scope: ""
                  rules:
                    - actions: ["invoke", "invoke_membership", "register", "deregister"]
                      effect: EFFECT_ALLOW
                      roles: ["platform_admin"]
                    - actions: ["invoke"]
                      effect: EFFECT_ALLOW
                      roles: ["relationship_manager"]
                """.formatted(BundleCanonicalizer.BUNDLE_VERSION_SENTINEL);
    }

    private GenericContainer<?> cerbos(String confDir, String policyDir) {
        return new GenericContainer<>(CERBOS_IMAGE)
                .withExposedPorts(3592)
                .withFileSystemBind(confDir, "/conf", BindMode.READ_ONLY)
                // The runtime policies volume: iam-service (this test) writes on the host side; the PDP
                // reads it read-only under its watched directory — exactly the demo topology.
                .withFileSystemBind(policyDir, "/policies", BindMode.READ_ONLY)
                .withCommand("server", "--config=/conf/config.yaml")
                .waitingFor(Wait.forHttp("/_cerbos/health").forPort(3592).forStatusCode(200)
                        .withStartupTimeout(Duration.ofSeconds(90)));
    }

    /** One real CheckResources against the PDP at {@code policyVersion}; returns the effect for tuple T. */
    private String decide(String baseUrl, String policyVersion) throws Exception {
        String body = """
                {"principal":{"id":"rm-1","policyVersion":"%s","roles":["%s"],"attr":{}},
                 "resources":[{"actions":["%s"],
                  "resource":{"kind":"agent","policyVersion":"%s","scope":"","id":"a1","attr":{}}}]}
                """.formatted(policyVersion, TUPLE_ROLE, TUPLE_ACTION, policyVersion);
        HttpResponse<String> resp = HttpClient.newHttpClient().send(
                HttpRequest.newBuilder()
                        .uri(URI.create(baseUrl + "/api/check/resources"))
                        .header("Content-Type", "application/json")
                        .POST(HttpRequest.BodyPublishers.ofString(body))
                        .build(),
                HttpResponse.BodyHandlers.ofString());
        assertThat(resp.statusCode()).as("check body: %s", resp.body()).isEqualTo(200);
        return JSON.readTree(resp.body()).path("results").path(0).path("actions").path(TUPLE_ACTION).asText();
    }

    /** Poll until the PDP's decision at {@code policyVersion} reaches {@code want}, or time out. */
    private String awaitDecision(String baseUrl, String policyVersion, String want) throws Exception {
        String last = "";
        long deadline = System.currentTimeMillis() + Duration.ofSeconds(40).toMillis();
        while (System.currentTimeMillis() < deadline) {
            last = decide(baseUrl, policyVersion);
            if (want.equals(last)) return last;
            Thread.sleep(500);
        }
        return last;
    }

    @Test
    void promotionLoadFlipsALiveDecisionAndIsAdditive() throws Exception {
        requireDocker();

        Path work = Files.createTempDirectory("promotion-runtime-enforce-");
        Path conf = work.resolve("conf");
        Path policies = work.resolve("policies");
        Files.createDirectories(conf);
        Files.createDirectories(policies);

        // The SAME storage config the demo runs: disk + watchForChanges. The watched dir is the writable
        // runtime-policies volume the loader writes into.
        Files.writeString(conf.resolve("config.yaml"), """
                server:
                  httpListenAddr: ":3592"
                storage:
                  driver: "disk"
                  disk:
                    directory: /policies
                    watchForChanges: true
                """);

        // ── 1. Base bundle present at startup: version=default, DENIES tuple T. ──
        Files.writeString(policies.resolve("agent_base.yaml"), baseBundle(), StandardCharsets.UTF_8);

        // The promoted candidate as an immutable, content-addressed bundle (sentinel form → materialize).
        PolicyBundle candidate = PolicyBundle.materialize(
                "acme",
                List.of(new BundleFile("agent@acme.yaml", candidateSentinelBundle())),
                List.of("manifest:agent@sha-s1"),
                new BundleTestMetadata("fixtures-s1", 1, "c3-independent-oracle", "cerbos:0.53.0"),
                new BundleCanonicalizer());
        String bundleId = candidate.bundleId();

        try (GenericContainer<?> pdp = cerbos(conf.toString(), policies.toString())) {
            pdp.start();
            String base = "http://" + pdp.getHost() + ":" + pdp.getMappedPort(3592);

            // ── 1. Assert base DENIES tuple T at policyVersion=default. ──
            String beforeDefault = decide(base, "default");
            assertThat(beforeDefault)
                    .as("base bundle must DENY tuple T at policyVersion=default before promotion")
                    .isEqualTo("EFFECT_DENY");

            // Sanity: the promoted version is unknown to the PDP yet ⇒ DENY (no version=<bundleId> policy).
            assertThat(decide(base, bundleId))
                    .as("the promoted version must not exist in the PDP before the load step")
                    .isEqualTo("EFFECT_DENY");

            // ── 2. Run the REAL production load step against the watched dir. ──
            PromotedBundleLoader loader = new PromotedBundleLoader(policies.toString());
            List<Path> written = loader.load(candidate);
            assertThat(written).as("the loader must materialise the promoted bundle's policies").isNotEmpty();

            // ── 3. After watchForChanges reloads, the promoted version now ALLOWS tuple T. ──
            String afterPromoted = awaitDecision(base, bundleId, "EFFECT_ALLOW");
            assertThat(afterPromoted)
                    .as("promotion must flip a LIVE PDP decision: policyVersion=%s must ALLOW tuple T "
                            + "after the runtime load + watch reload", bundleId)
                    .isEqualTo("EFFECT_ALLOW");

            // ── 4. The base default version is UNCHANGED — additive, not destructive. ──
            assertThat(decide(base, "default"))
                    .as("the promoted bundle must be additive: policyVersion=default must STILL DENY T")
                    .isEqualTo("EFFECT_DENY");
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
     * Docker gate (H7 idiom). Locally a missing daemon is an assume-skip so the unit suite still runs; in
     * CI ({@code CONDUIT_DOCKER_REQUIRED=true}) the skip becomes a HARD FAILURE — this promotion-reaches-
     * enforcement proof must RUN, not silently pass green.
     */
    private static void requireDocker() {
        boolean docker = dockerAvailable();
        boolean requiredInCi = Boolean.parseBoolean(
                System.getenv().getOrDefault("CONDUIT_DOCKER_REQUIRED", "false"));
        if (requiredInCi) {
            assertThat(docker)
                    .as("CONDUIT_DOCKER_REQUIRED=true (CI) but Docker is unavailable — this live-PDP "
                            + "promotion proof must RUN, not skip green")
                    .isTrue();
        } else {
            Assumptions.assumeTrue(docker, "Docker not available — skipping the S1 runtime-enforcement headline");
        }
    }
}
