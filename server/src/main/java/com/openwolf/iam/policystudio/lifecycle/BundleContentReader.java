package com.openwolf.iam.policystudio.lifecycle;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;

/**
 * Reconstructs the per-file map from a stored bundle's canonical bytes (the exact form {@link
 * BundleCanonicalizer#canonicalContent} emits and {@link PolicyBundleRecord} retains). It is the read side
 * of C5's content-addressed store: given the immutable record's canonical content, recover the individual
 * policy files — in particular the tenant restriction child — so the grounding provider can materialise a
 * tenant's ACTUAL active bundle as the review's {@code current} baseline (S3, Bug A).
 *
 * <p>The canonical layout is a fixed grammar: a {@code bundle-v1} header, {@code tenant=...}, a run of
 * {@code FILE:<path>} blocks (each followed by its normalised YAML), then {@code MANIFESTS:} and
 * {@code TESTS:} trailers. A file block ends at the next {@code FILE:} line or the {@code MANIFESTS:}
 * trailer.
 */
public final class BundleContentReader {

    private BundleContentReader() {}

    private static final String FILE_PREFIX = "FILE:";
    private static final String MANIFESTS = "MANIFESTS:";

    /** Recover {@code path → yaml} for every file block in the canonical content, in emitted order. */
    public static Map<String, String> filesFrom(String canonicalContent) {
        Map<String, String> files = new LinkedHashMap<>();
        if (canonicalContent == null || canonicalContent.isBlank()) {
            return files;
        }
        String[] lines = canonicalContent.replace("\r\n", "\n").replace('\r', '\n').split("\n", -1);
        String currentPath = null;
        StringBuilder body = new StringBuilder();
        for (String line : lines) {
            if (line.startsWith(FILE_PREFIX)) {
                flush(files, currentPath, body);
                currentPath = line.substring(FILE_PREFIX.length());
                body = new StringBuilder();
            } else if (line.equals(MANIFESTS)) {
                flush(files, currentPath, body);
                currentPath = null;
                break; // manifests + tests trailers are not file blocks
            } else if (currentPath != null) {
                body.append(line).append('\n');
            }
        }
        flush(files, currentPath, body);
        return files;
    }

    /**
     * The tenant restriction child yaml — the one file whose bundle path carries the {@code resource@tenant}
     * marker (base scope-chain / derived-role files never do). Empty if the bundle is base-only.
     */
    public static Optional<String> tenantChildYaml(String canonicalContent) {
        return filesFrom(canonicalContent).entrySet().stream()
                .filter(e -> e.getKey().contains("@"))
                .map(Map.Entry::getValue)
                .findFirst();
    }

    /** Recover a specific tenant child by resource kind from a tenant-wide C5 bundle. */
    public static Optional<String> tenantChildYaml(String canonicalContent, String resourceKind,
                                                    String tenantId) {
        if (resourceKind == null || tenantId == null) {
            return Optional.empty();
        }
        String expected = "policies/" + resourceKind + "@" + tenantId + ".yaml";
        return Optional.ofNullable(filesFrom(canonicalContent).get(expected));
    }

    private static void flush(Map<String, String> files, String path, StringBuilder body) {
        if (path != null && !path.isBlank()) {
            files.put(path, body.toString().stripTrailing() + "\n");
        }
    }
}
