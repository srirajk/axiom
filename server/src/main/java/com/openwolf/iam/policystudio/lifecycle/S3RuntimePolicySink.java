package com.openwolf.iam.policystudio.lifecycle;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.core.client.config.ClientOverrideConfiguration;
import software.amazon.awssdk.core.retry.RetryPolicy;
import software.amazon.awssdk.core.sync.RequestBody;
import software.amazon.awssdk.http.apache.ApacheHttpClient;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.S3Configuration;
import software.amazon.awssdk.services.s3.model.CreateBucketRequest;
import software.amazon.awssdk.services.s3.model.HeadBucketRequest;
import software.amazon.awssdk.services.s3.model.ListObjectsV2Request;
import software.amazon.awssdk.services.s3.model.NoSuchBucketException;
import software.amazon.awssdk.services.s3.model.PutObjectRequest;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;

/**
 * The S3-family object-store sink for promoted runtime policy bundles — the blob-storage counterpart of the
 * {@link PromotedBundleLoader}'s legacy file-volume write. Cerbos runs its {@code blob} storage driver
 * against the SAME bucket and <b>polls</b> it on {@code updatePollInterval}; writing a bundle here (each
 * policy stamped {@code version=<bundleId>}) makes a Policy Studio promotion reach runtime enforcement
 * through a poll — with none of the macOS-VirtioFS host→container inotify event loss the disk +
 * {@code watchForChanges} path suffered.
 *
 * <p>Role-first name for the S3-family
 * adapter; MinIO is merely the configured endpoint (the same class serves AWS S3 / R2 / GCS-interop). Every
 * setting is injected (bucket / prefix / endpoint / region / path-style / credentials) — no hardcoded
 * endpoint or bucket. Keys are written under {@code <prefix>/<bundle-namespaced-name>} so a promoted
 * {@code version=<bundleId>} bundle coexists additively with the seeded {@code base/} policy set the same
 * bucket serves.
 */
public final class S3RuntimePolicySink {

    private static final Logger log = LoggerFactory.getLogger(S3RuntimePolicySink.class);

    private final String bucket;
    private final String prefix;
    private final S3Client s3;

    /**
     * @param bucket    the bucket Cerbos serves policies from (also holds the seeded {@code base/} set). Must be non-blank.
     * @param prefix    the key prefix promoted bundles are written under (e.g. {@code runtime}); Cerbos reads the whole bucket.
     * @param endpoint  the S3 endpoint override (e.g. {@code http://minio:9000}); blank ⇒ real AWS endpoint for the region.
     * @param region    the region label (MinIO ignores it but the SDK requires one).
     * @param pathStyle path-style addressing (required for MinIO / most S3-compatible stores).
     * @param accessKey static access key; blank ⇒ default credential provider chain.
     * @param secretKey static secret key.
     */
    public S3RuntimePolicySink(String bucket, String prefix, String endpoint, String region,
                               boolean pathStyle, String accessKey, String secretKey) {
        if (bucket == null || bucket.isBlank()) {
            throw new IllegalArgumentException("S3RuntimePolicySink requires a non-blank bucket");
        }
        this.bucket = bucket.trim();
        this.prefix = prefix == null ? "" : prefix.trim().replaceAll("^/+|/+$", "");

        // Bounded sync client — the promotion is off the request path (control plane), but a stalled store
        // must still fail the load within a finite window rather than hang the promotion transaction.
        var http = ApacheHttpClient.builder()
                .maxConnections(4)
                .connectionAcquisitionTimeout(Duration.ofSeconds(5))
                .connectionTimeout(Duration.ofSeconds(5))
                .socketTimeout(Duration.ofSeconds(15));
        var builder = S3Client.builder()
                .region(Region.of(region == null || region.isBlank() ? "us-east-1" : region))
                .httpClientBuilder(http)
                .overrideConfiguration(ClientOverrideConfiguration.builder()
                        .apiCallTimeout(Duration.ofSeconds(30))
                        .apiCallAttemptTimeout(Duration.ofSeconds(15))
                        .retryPolicy(RetryPolicy.none())
                        .build())
                .serviceConfiguration(S3Configuration.builder().pathStyleAccessEnabled(pathStyle).build());
        if (endpoint != null && !endpoint.isBlank()) {
            builder.endpointOverride(URI.create(endpoint));
        }
        if (accessKey != null && !accessKey.isBlank()) {
            builder.credentialsProvider(StaticCredentialsProvider.create(
                    AwsBasicCredentials.create(accessKey, secretKey)));
        }
        this.s3 = builder.build();
        ensureBucket();
        log.info("PromotedBundleLoader → blob sink {} bucket='{}' prefix='{}'",
                endpoint == null || endpoint.isBlank() ? region : endpoint, this.bucket,
                this.prefix.isBlank() ? "(root)" : this.prefix);
    }

    /**
     * Write the bundle's version-stamped policy objects, in the given (ancestor-first) iteration order, under
     * {@code <prefix>/<name>}. Returns the object keys written. Idempotent: a re-promotion of the same
     * bundleId overwrites byte-identical objects at the same keys, so a poll re-reads the same snapshot.
     */
    public List<String> write(LinkedHashMap<String, String> objectsByName) {
        List<String> keys = new ArrayList<>();
        for (var e : objectsByName.entrySet()) {
            String key = prefix.isBlank() ? e.getKey() : prefix + "/" + e.getKey();
            s3.putObject(PutObjectRequest.builder()
                            .bucket(bucket)
                            .key(key)
                            .contentType("application/yaml")
                            .build(),
                    RequestBody.fromString(e.getValue(), StandardCharsets.UTF_8));
            keys.add(key);
        }
        return keys;
    }

    /**
     * Read the serving store's object inventory. This is deliberately an inventory of the configured
     * runtime prefix, not a control-plane count: recovery must prove that the same authoritative store is
     * reachable after a crash. Keys and provider ETags are returned in a stable form for hashing by the
     * caller; no secret/object content is exposed.
     */
    public List<String> snapshotEntries() {
        List<String> entries = new ArrayList<>();
        String continuation = null;
        do {
            var requestBuilder = ListObjectsV2Request.builder().bucket(bucket);
            if (!prefix.isBlank()) requestBuilder.prefix(prefix + "/");
            if (continuation != null) requestBuilder.continuationToken(continuation);
            var request = requestBuilder.build();
            var response = s3.listObjectsV2(request);
            response.contents().forEach(object -> entries.add(object.key() + "|" + object.eTag()));
            continuation = Boolean.TRUE.equals(response.isTruncated()) ? response.nextContinuationToken() : null;
        } while (continuation != null);
        entries.sort(String::compareTo);
        return List.copyOf(entries);
    }

    /** Best-effort: the demo's minio-init already creates the bucket; ensure it exists so a fresh env still works. */
    private void ensureBucket() {
        try {
            s3.headBucket(HeadBucketRequest.builder().bucket(bucket).build());
        } catch (NoSuchBucketException e) {
            try {
                s3.createBucket(CreateBucketRequest.builder().bucket(bucket).build());
                log.info("PromotedBundleLoader blob sink created bucket '{}'", bucket);
            } catch (RuntimeException ce) {
                log.warn("PromotedBundleLoader blob sink could not create bucket '{}': {}", bucket, ce.getMessage());
            }
        } catch (RuntimeException e) {
            // Endpoint unreachable at boot must not take iam-service down; a promotion write will fail fast
            // (fail-closed) and roll back the CAS, exactly as an unwritable runtime volume did before.
            log.warn("PromotedBundleLoader blob sink bucket preflight failed for '{}': {}", bucket, e.getMessage());
        }
    }
}
