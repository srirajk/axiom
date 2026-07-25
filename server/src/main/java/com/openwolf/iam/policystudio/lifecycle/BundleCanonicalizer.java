package com.openwolf.iam.policystudio.lifecycle;

import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;

/**
 * Canonicalises a full policy bundle to reproducible bytes and derives its content-addressed identity
 * (Axiom Story C5). The canonical form is:
 *
 * <ul>
 *   <li><b>UTF-8, LF only</b> — every CRLF/CR is normalised to LF and trailing whitespace on each line
 *       is stripped;</li>
 *   <li><b>sorted file paths</b> — files are emitted in path order, so bundle assembly order can never
 *       change the id;</li>
 *   <li><b>normalized YAML</b> — each file body is whitespace-normalised (the caller supplies canonical
 *       YAML from {@code CanonicalPolicyWriter}; this only guards line endings);</li>
 *   <li><b>no timestamps</b> — nothing wall-clock enters the hash input;</li>
 *   <li><b>every policy version replaced by {@link #BUNDLE_VERSION_SENTINEL}</b> — a policy in the
 *       bundle uses the <em>bundle id</em> as its {@code policyVersion}, which would make the hash
 *       reference itself. Substituting the sentinel in the hash input breaks that self-reference and
 *       keeps the id reproducible; the concrete id is stamped back in only when the bundle is
 *       {@link PolicyBundle#renderedFiles() rendered} for staging/compile.</li>
 * </ul>
 *
 * <p>{@code bundleId = "b_" + sha256(canonicalBytes)}. Same bundle content ⇒ same id; a one-byte change
 * in any file, manifest ref, or test metadata ⇒ a different id — which is what makes the promotion CAS,
 * the staleness check, and the examiner join trustworthy.
 */
@Component
public class BundleCanonicalizer {

    /** The reproducible, no-self-reference placeholder every policy version collapses to in the hash. */
    public static final String BUNDLE_VERSION_SENTINEL = "__BUNDLE_VERSION__";

    /** The content-addressed id prefix. */
    public static final String BUNDLE_ID_PREFIX = "b_";

    /**
     * Canonical bytes for a bundle. The {@code files} MUST already carry the version sentinel in their
     * policyVersion position (candidates are authored that way); as a belt-and-braces guard any literal
     * occurrence of {@code selfId} is also collapsed to the sentinel so re-hashing a materialised bundle
     * is stable.
     */
    public String canonicalContent(String tenantId, List<BundleFile> files, List<String> manifestRefs,
                                    BundleTestMetadata testMetadata, String selfId) {
        StringBuilder sb = new StringBuilder();
        sb.append("bundle-v1\n");
        sb.append("tenant=").append(tenantId).append('\n');

        List<BundleFile> sorted = new ArrayList<>(files);
        sorted.sort(Comparator.comparing(BundleFile::path));
        for (BundleFile f : sorted) {
            sb.append("FILE:").append(f.path()).append('\n');
            sb.append(normalise(f.yaml(), selfId)).append('\n');
        }

        List<String> manifests = new ArrayList<>(manifestRefs);
        manifests.sort(Comparator.naturalOrder());
        sb.append("MANIFESTS:\n");
        for (String m : manifests) {
            sb.append(m).append('\n');
        }

        sb.append("TESTS:\n").append(testMetadata.canonical()).append('\n');
        return sb.toString();
    }

    /** Derive the content-addressed id from canonical bytes. */
    public String bundleId(String canonicalContent) {
        return BUNDLE_ID_PREFIX + BundleHashing.sha256Hex(canonicalContent);
    }

    /**
     * Normalise one file body: LF line endings, trailing whitespace stripped per line, and any literal
     * occurrence of the bundle's own id collapsed to the version sentinel (no self-reference).
     */
    private String normalise(String yaml, String selfId) {
        String lf = yaml.replace("\r\n", "\n").replace('\r', '\n');
        if (selfId != null && !selfId.isBlank()) {
            lf = lf.replace(selfId, BUNDLE_VERSION_SENTINEL);
        }
        StringBuilder out = new StringBuilder(lf.length());
        for (String line : lf.split("\n", -1)) {
            out.append(stripTrailing(line)).append('\n');
        }
        // collapse the trailing newline the split added back to a single one
        while (out.length() >= 2 && out.charAt(out.length() - 1) == '\n' && out.charAt(out.length() - 2) == '\n') {
            out.setLength(out.length() - 1);
        }
        return out.toString().stripTrailing();
    }

    private static String stripTrailing(String s) {
        int end = s.length();
        while (end > 0 && Character.isWhitespace(s.charAt(end - 1))) {
            end--;
        }
        return s.substring(0, end);
    }
}
