package com.openwolf.iam.policystudio.lifecycle;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.Network;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.utility.DockerImageName;
import org.testcontainers.utility.MountableFile;
import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.core.sync.RequestBody;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.S3Configuration;
import software.amazon.awssdk.services.s3.model.CreateBucketRequest;
import software.amazon.awssdk.services.s3.model.PutObjectRequest;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.List;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * THE HEADLINE for the blob-storage migration: a promotion flips a live PDP decision through the MinIO
 * {@code blob} storage driver — Cerbos <b>polls</b> the bucket, it never file-watches. Proven end to end
 * against a REAL Cerbos-on-blob + a REAL MinIO, both on an ephemeral Testcontainers network (never the
 * demo's {@code conduit-cerbos} / {@code conduit-minio}).
 *
 * <p>Cerbos has ONE storage driver, so this test exercises the full constraint: the base scope-chain AND the
 * promoted runtime bundle both come from the one bucket. The base is seeded to {@code s3://cerbos-policies/base/}
 * before Cerbos starts (exactly what {@code minio-init} does for the demo); the REAL {@link PromotedBundleLoader}
 * — via {@link S3RuntimePolicySink}, the production write path — writes the promoted bundle to
 * {@code s3://cerbos-policies/runtime/}.
 *
 * <ol>
 *   <li>Seed the realistic base ({@code version: default}, imports {@code business_derived_roles}) that DENIES
 *       tuple T; assert a real {@code CheckResources} at {@code policyVersion=default} DENIES.</li>
 *   <li>Run the REAL loader to write a promoted candidate ({@code version=<bundleId>}, ALLOWs T) to the bucket.</li>
 *   <li>After one {@code updatePollInterval}, assert {@code policyVersion=<bundleId>} now ALLOWS T — the poll
 *       reached enforcement, with NO file-watch.</li>
 *   <li>Assert {@code policyVersion=default} STILL DENIES T — the promoted bundle is additive.</li>
 * </ol>
 *
 * <p>A second test is the "all authz breaks" guard: with ONLY the seeded base in the bucket, Cerbos-on-blob
 * answers a known base decision correctly — proving the base seed is complete (an incomplete seed, e.g.
 * missing {@code business_derived_roles}, would fail to compile and serve NO policies).
 */
class PromotionReachesRuntimeEnforcementBlobIT {

    private static final DockerImageName CERBOS_IMAGE = DockerImageName.parse(
            System.getenv().getOrDefault("CERBOS_IMAGE", "ghcr.io/cerbos/cerbos:0.53.0"));
    private static final DockerImageName MINIO_IMAGE = DockerImageName.parse(
            System.getenv().getOrDefault("MINIO_IMAGE", "minio/minio:latest"));

    private static final ObjectMapper JSON = new ObjectMapper();

    private static final String BUCKET = "cerbos-policies";
    private static final String BASE_PREFIX = "base";
    private static final String RUNTIME_PREFIX = "runtime";
    private static final String MINIO_USER = "minio";
    private static final String MINIO_PASSWORD = "miniosecret";
    private static final String REGION = "us-east-1";
    private static final short POLL_SECONDS = 5;

    /** Tuple T: a relationship_manager invoking the {@code agent} resource. Base denies; the candidate allows. */
    private static final String TUPLE_ROLE = "relationship_manager";
    private static final String TUPLE_ACTION = "invoke";

    /** The version-stamped candidate: ADDS an unconditional ALLOW for tuple T at the root scope. */
    private static String candidateSentinelBundle() {
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

    // ── the shared network + containers ──────────────────────────────────────────────────────────

    private static GenericContainer<?> minio(Network network) {
        return new GenericContainer<>(MINIO_IMAGE)
                .withNetwork(network)
                .withNetworkAliases("minio")
                .withEnv("MINIO_ROOT_USER", MINIO_USER)
                .withEnv("MINIO_ROOT_PASSWORD", MINIO_PASSWORD)
                .withCommand("server", "/data")
                .withExposedPorts(9000)
                .waitingFor(Wait.forHttp("/minio/health/ready").forPort(9000)
                        .withStartupTimeout(Duration.ofSeconds(90)));
    }

    private static GenericContainer<?> cerbosOnBlob(Network network, Path confDir) {
        return new GenericContainer<>(CERBOS_IMAGE)
                .withNetwork(network)
                .withExposedPorts(3592)
                .withCopyFileToContainer(MountableFile.forHostPath(confDir.resolve("config.yaml")),
                        "/conf/config.yaml")
                // Cerbos blob driver reads bucket creds from the standard AWS env — exactly the demo wiring.
                .withEnv("AWS_ACCESS_KEY_ID", MINIO_USER)
                .withEnv("AWS_SECRET_ACCESS_KEY", MINIO_PASSWORD)
                .withEnv("AWS_REGION", REGION)
                .withCommand("server", "--config=/conf/config.yaml")
                .waitingFor(Wait.forHttp("/_cerbos/health").forPort(3592).forStatusCode(200)
                        .withStartupTimeout(Duration.ofSeconds(90)));
    }

    /** The blob storage config: Cerbos serves the WHOLE bucket (base/ + runtime/) and POLLS it — no file-watch. */
    private static void writeBlobConfig(Path confDir) throws Exception {
        Files.writeString(confDir.resolve("config.yaml"), """
                server:
                  httpListenAddr: ":3592"
                storage:
                  driver: "blob"
                  blob:
                    bucket: "s3://%s?endpoint=http://minio:9000&hostname_immutable=true&region=%s"
                    workDir: /tmp/cerbos/blob
                    updatePollInterval: %ds
                    downloadTimeout: 30s
                    requestTimeout: 10s
                """.formatted(BUCKET, REGION, POLL_SECONDS));
    }

    // ── S3 helpers (host side, via the mapped MinIO port) ────────────────────────────────────────

    private static S3Client s3(GenericContainer<?> minio) {
        return S3Client.builder()
                .region(Region.of(REGION))
                .endpointOverride(URI.create("http://" + minio.getHost() + ":" + minio.getMappedPort(9000)))
                .credentialsProvider(StaticCredentialsProvider.create(
                        AwsBasicCredentials.create(MINIO_USER, MINIO_PASSWORD)))
                .serviceConfiguration(S3Configuration.builder().pathStyleAccessEnabled(true).build())
                .build();
    }

    private static void seedBase(S3Client s3) throws Exception {
        s3.createBucket(CreateBucketRequest.builder().bucket(BUCKET).build());
        // Seed the realistic base (agent_resource + business_derived_roles) under base/ — mirrors minio-init.
        Path baseDir = Path.of(
                PromotionReachesRuntimeEnforcementBlobIT.class.getResource("/policystudio/base-bundle").toURI());
        try (Stream<Path> files = Files.walk(baseDir)) {
            List<Path> yamls = files.filter(p -> p.toString().endsWith(".yaml")).toList();
            for (Path p : yamls) {
                s3.putObject(PutObjectRequest.builder()
                                .bucket(BUCKET)
                                .key(BASE_PREFIX + "/" + p.getFileName())
                                .contentType("application/yaml")
                                .build(),
                        RequestBody.fromString(Files.readString(p), StandardCharsets.UTF_8));
            }
        }
    }

    /** One real CheckResources against the PDP at {@code policyVersion}; returns the effect for tuple T. */
    private static String decide(String baseUrl, String policyVersion) throws Exception {
        String body = """
                {"principal":{"id":"rm-1","policyVersion":"%s","roles":["%s"],
                  "attr":{"segments":{},"tenant_id":""}},
                 "resources":[{"actions":["%s"],
                  "resource":{"kind":"agent","policyVersion":"%s","scope":"","id":"a1",
                   "attr":{"domain":"wealth-management","audience":"segment","access_mode":"read",
                           "data_classification":"confidential","tenant_id":""}}}]}
                """.formatted(policyVersion, TUPLE_ROLE, TUPLE_ACTION, policyVersion);
        return effect(baseUrl, body, TUPLE_ACTION);
    }

    /** Generic CheckResources: returns the effect string for {@code action} in the first result. */
    private static String effect(String baseUrl, String body, String action) throws Exception {
        HttpResponse<String> resp = HttpClient.newHttpClient().send(
                HttpRequest.newBuilder()
                        .uri(URI.create(baseUrl + "/api/check/resources"))
                        .header("Content-Type", "application/json")
                        .POST(HttpRequest.BodyPublishers.ofString(body))
                        .build(),
                HttpResponse.BodyHandlers.ofString());
        assertThat(resp.statusCode()).as("check body: %s", resp.body()).isEqualTo(200);
        return JSON.readTree(resp.body()).path("results").path(0).path("actions").path(action).asText();
    }

    /** Poll until the PDP's decision at {@code policyVersion} reaches {@code want}, or time out. */
    private static String awaitDecision(String baseUrl, String policyVersion, String want) throws Exception {
        String last = "";
        long deadline = System.currentTimeMillis() + Duration.ofSeconds(60).toMillis();
        while (System.currentTimeMillis() < deadline) {
            last = decide(baseUrl, policyVersion);
            if (want.equals(last)) return last;
            Thread.sleep(500);
        }
        return last;
    }

    // ── the headline: promote → bucket → poll → enforce, no file-watch ──────────────────────────

    @Test
    void promotionThroughBlobPollFlipsALiveDecisionAndIsAdditive() throws Exception {
        requireDocker();
        Path conf = Files.createTempDirectory("cerbos-blob-conf-");
        writeBlobConfig(conf);

        // The promoted candidate as an immutable, content-addressed bundle (sentinel form → materialize).
        PolicyBundle candidate = PolicyBundle.materialize(
                "acme",
                List.of(new BundleFile("agent@acme.yaml", candidateSentinelBundle())),
                List.of("manifest:agent@sha-blob"),
                new BundleTestMetadata("fixtures-blob", 1, "c3-independent-oracle", "cerbos:0.53.0"),
                new BundleCanonicalizer());
        String bundleId = candidate.bundleId();

        try (Network network = Network.newNetwork();
             GenericContainer<?> minio = minio(network)) {
            minio.start();
            try (S3Client s3 = s3(minio)) {
                seedBase(s3);   // base only → base DENIES T; runtime/ still empty

                try (GenericContainer<?> pdp = cerbosOnBlob(network, conf)) {
                    pdp.start();
                    String base = "http://" + pdp.getHost() + ":" + pdp.getMappedPort(3592);

                    // ── 1. Base (served from blob) DENIES tuple T at policyVersion=default. ──
                    assertThat(awaitDecision(base, "default", "EFFECT_DENY"))
                            .as("base bundle served from the bucket must DENY tuple T at policyVersion=default")
                            .isEqualTo("EFFECT_DENY");
                    // The promoted version does not exist yet ⇒ DENY.
                    assertThat(decide(base, bundleId))
                            .as("the promoted version must not exist in the bucket before the load step")
                            .isEqualTo("EFFECT_DENY");

                    // ── 2. Run the REAL production load step: write the promoted bundle to the bucket via S3. ──
                    S3RuntimePolicySink sink = new S3RuntimePolicySink(
                            BUCKET, RUNTIME_PREFIX,
                            "http://" + minio.getHost() + ":" + minio.getMappedPort(9000),
                            REGION, true, MINIO_USER, MINIO_PASSWORD);
                    PromotedBundleLoader loader = new PromotedBundleLoader(sink);
                    List<Path> written = loader.load(candidate);
                    assertThat(written)
                            .as("the loader must write the promoted bundle's objects to the runtime prefix")
                            .isNotEmpty();

                    // ── 3. After the poll interval, the promoted version ALLOWS tuple T — poll, not watch. ──
                    assertThat(awaitDecision(base, bundleId, "EFFECT_ALLOW"))
                            .as("promotion must flip a LIVE PDP decision through the blob POLL: "
                                    + "policyVersion=%s must ALLOW tuple T after the write + one poll", bundleId)
                            .isEqualTo("EFFECT_ALLOW");

                    // ── 4. The base default version is UNCHANGED — additive, not destructive. ──
                    assertThat(decide(base, "default"))
                            .as("the promoted bundle must be additive: policyVersion=default must STILL DENY T")
                            .isEqualTo("EFFECT_DENY");
                }
            }
        }
    }

    // ── the "all authz breaks" guard: base served from blob answers a known decision ────────────

    @Test
    void baseServedFromBlobAnswersAKnownDecision() throws Exception {
        requireDocker();
        Path conf = Files.createTempDirectory("cerbos-blob-smoke-conf-");
        writeBlobConfig(conf);

        try (Network network = Network.newNetwork();
             GenericContainer<?> minio = minio(network)) {
            minio.start();
            try (S3Client s3 = s3(minio)) {
                seedBase(s3);   // ONLY the base — no runtime bundle

                try (GenericContainer<?> pdp = cerbosOnBlob(network, conf)) {
                    pdp.start();
                    String base = "http://" + pdp.getHost() + ":" + pdp.getMappedPort(3592);

                    // KNOWN ALLOW: platform_admin invoking an agent (unconditional base rule) — proves the base
                    // set (agent_resource + its imported business_derived_roles) compiled and serves from blob.
                    String adminAllow = """
                            {"principal":{"id":"admin-1","policyVersion":"default","roles":["platform_admin"],
                              "attr":{"segments":{},"tenant_id":""}},
                             "resources":[{"actions":["invoke"],
                              "resource":{"kind":"agent","policyVersion":"default","scope":"","id":"a1",
                               "attr":{"domain":"wealth-management","audience":"segment","access_mode":"read",
                                       "data_classification":"confidential","tenant_id":""}}}]}
                            """;
                    assertThat(awaitAllow(base, adminAllow))
                            .as("base served from blob must ALLOW platform_admin invoke (the seed is complete)")
                            .isEqualTo("EFFECT_ALLOW");

                    // KNOWN DENY: a chat_user with NO segment membership fails the classification gate.
                    String userDeny = """
                            {"principal":{"id":"u-1","policyVersion":"default","roles":["chat_user"],
                              "attr":{"segments":{},"tenant_id":""}},
                             "resources":[{"actions":["invoke"],
                              "resource":{"kind":"agent","policyVersion":"default","scope":"","id":"a1",
                               "attr":{"domain":"wealth-management","audience":"segment","access_mode":"read",
                                       "data_classification":"confidential","tenant_id":""}}}]}
                            """;
                    assertThat(effect(base, userDeny, "invoke"))
                            .as("base served from blob must DENY a chat_user with no segment membership")
                            .isEqualTo("EFFECT_DENY");
                }
            }
        }
    }

    /** Poll the ALLOW decision until it lands (base has to compile from the freshly seeded bucket first). */
    private static String awaitAllow(String baseUrl, String body) throws Exception {
        String last = "";
        long deadline = System.currentTimeMillis() + Duration.ofSeconds(60).toMillis();
        while (System.currentTimeMillis() < deadline) {
            last = effect(baseUrl, body, "invoke");
            if ("EFFECT_ALLOW".equals(last)) return last;
            Thread.sleep(500);
        }
        return last;
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
     * Docker gate. Locally a missing daemon is an assume-skip; in CI ({@code CONDUIT_DOCKER_REQUIRED=true})
     * the skip becomes a HARD FAILURE — this blob promote→poll→enforce proof must RUN, not silently pass green.
     */
    private static void requireDocker() {
        boolean docker = dockerAvailable();
        boolean requiredInCi = Boolean.parseBoolean(
                System.getenv().getOrDefault("CONDUIT_DOCKER_REQUIRED", "false"));
        if (requiredInCi) {
            assertThat(docker)
                    .as("CONDUIT_DOCKER_REQUIRED=true (CI) but Docker is unavailable — the blob "
                            + "promote→poll→enforce proof must RUN, not skip green")
                    .isTrue();
        } else {
            Assumptions.assumeTrue(docker, "Docker not available — skipping the blob runtime-enforcement headline");
        }
    }
}
