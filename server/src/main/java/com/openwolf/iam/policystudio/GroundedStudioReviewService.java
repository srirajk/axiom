package com.openwolf.iam.policystudio;

import com.openwolf.iam.policystudio.api.StudioSessionStore;
import com.openwolf.iam.policystudio.lifecycle.BundleCanonicalizer;
import com.openwolf.iam.policystudio.lifecycle.BundleContentReader;
import com.openwolf.iam.policystudio.lifecycle.BundleFile;
import com.openwolf.iam.policystudio.lifecycle.BundleTestMetadata;
import com.openwolf.iam.policystudio.lifecycle.PolicyBundle;
import com.openwolf.iam.policystudio.lifecycle.ResourcePolicyIdentity;
import com.openwolf.iam.policystudio.lifecycle.SelfContainedBundleAssembler;
import com.openwolf.iam.policystudio.lifecycle.StudioBaselineActivationService;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * The single server-side path that turns an <em>authored candidate policy</em> (canonical YAML) into a
 * consequence review, deriving <b>all grounding — vocabulary, base ceiling, current snapshot, and the
 * sampled fixture matrix — from the tenant's manifest</b> via {@link StudioGroundingProvider}. The only
 * caller-supplied inputs are the trusted principal's {@code tenant}/{@code author} (from the JWT, never a
 * body field) and the authored {@code canonicalYaml} + {@code resourceKind} selector.
 *
 * <p>This is the S2 trust boundary: no caller may hand in the two bundle snapshots, the vocabulary, or the
 * fixture matrix — those are the grounding, and grounding is server-derived here. Both the C4 review route
 * ({@code StudioReviewController}) and the grounded assemble route ({@code StudioGroundingController}) go
 * through this one collaborator, so there is exactly one derivation and no route can bypass it.
 */
@Service
public class GroundedStudioReviewService {

    private final StudioGroundingProvider grounding;
    private final PolicyYamlParser parser;
    private final CanonicalPolicyWriter writer;
    private final ConsequenceDiffService diff;
    private final ProductionPdpDecisionSource pdpSource;
    private final ObjectProvider<ConsequenceProseModelClient> prose;
    private final BundleCanonicalizer canonicalizer;
    private final StudioSessionStore store;
    private final StudioBaselineActivationService baselineActivation;
    private final SelfContainedBundleAssembler assembler;

    public GroundedStudioReviewService(StudioGroundingProvider grounding,
                                       PolicyYamlParser parser,
                                       CanonicalPolicyWriter writer,
                                       ConsequenceDiffService diff,
                                       ProductionPdpDecisionSource pdpSource,
                                       ObjectProvider<ConsequenceProseModelClient> prose,
                                       BundleCanonicalizer canonicalizer,
                                       StudioSessionStore store,
                                       StudioBaselineActivationService baselineActivation,
                                       SelfContainedBundleAssembler assembler) {
        this.grounding = grounding;
        this.parser = parser;
        this.writer = writer;
        this.diff = diff;
        this.pdpSource = pdpSource;
        this.prose = prose;
        this.canonicalizer = canonicalizer;
        this.store = store;
        this.baselineActivation = baselineActivation;
        this.assembler = assembler;
    }

    private static String resolveKind(String resourceKind) {
        return PlatformResourceKind.require(resourceKind);
    }

    /**
     * Compute a consequence review for an authored candidate, deriving all grounding server-side and
     * caching the review against the VERIFIED author + tenant. The {@code tenant}/{@code author} are the
     * principal's trusted identity; {@code canonicalYaml} is the authored candidate. Nothing else — no
     * snapshots, vocabulary, or matrix — crosses the trust boundary.
     */
    public ConsequenceReview assembleAndReview(String tenant, String author, String resourceKind, String canonicalYaml) {
        String kind = resolveKind(resourceKind);
        StudioGroundingSnapshot grounded = grounding.snapshot(tenant, kind);
        baselineActivation.ensureExplicitBaseline(tenant, grounded.current().bundleId());
        PolicyBundle bundle = materializeCandidate(tenant, grounded, canonicalYaml, grounded.matrix().fixtureSetHash());
        BundleSnapshot candidate = new BundleSnapshot(
                bundle.bundleId(),
                parser.parse(canonicalYaml),
                grounded.baseCeiling(),
                bundle.canonicalContent());
        ConsequenceReview review = diff.computeReview(
                tenant, grounded.vocabulary(), grounded.current(), candidate, grounded.matrix(), pdpSource);
        ConsequenceProseModelClient client = prose.getIfAvailable();
        if (client != null) {
            review = diff.attachProse(review, client);
        }
        store.putReview(tenant, author, review, bundle);
        return review;
    }

    /**
     * Materialize the self-contained candidate bundle for an authored policy, deriving grounding
     * (base root, manifest refs, matrix) server-side. {@code fixtureSetHash} is bundle test metadata,
     * not grounding, so a caller override is honoured where the route allows it.
     */
    public PolicyBundle assembleCandidateBundle(String tenant, String resourceKind, String canonicalYaml, String fixtureSetHash) {
        String kind = resolveKind(resourceKind);
        StudioGroundingSnapshot grounded = grounding.snapshot(tenant, kind);
        String hash = fixtureSetHash == null || fixtureSetHash.isBlank() ? grounded.matrix().fixtureSetHash() : fixtureSetHash;
        return materializeCandidate(tenant, grounded, canonicalYaml, hash);
    }

    private PolicyBundle materializeCandidate(String tenant, StudioGroundingSnapshot grounded,
                                              String canonicalYaml, String fixtureSetHash) {
        PolicyIR parsed = parser.parse(canonicalYaml);
        PolicyIR sentinel = new PolicyIR(
                parsed.apiVersion(),
                BundleCanonicalizer.BUNDLE_VERSION_SENTINEL,
                parsed.resource(),
                tenant,
                parsed.scopePermissions(),
                parsed.importDerivedRoles(),
                parsed.rules());
        String yaml = writer.write(sentinel);
        BundleTestMetadata metadata = new BundleTestMetadata(
                fixtureSetHash,
                grounded.matrix().cells().size(),
                "manifest-grounded-sampled-matrix",
                "cerbos-0.53.0");
        // C5 has ONE activePolicyVersion per tenant. Capture every resource kind, then carry forward every
        // tenant child from the current immutable bundle and replace only the child being edited. This makes
        // the candidate a genuine tenant-wide snapshot over the platform policy resources.
        // all resolve at the same bundle id, while a shared-base change naturally rebases the whole tenant.
        Map<String, BundleFile> byPath = new LinkedHashMap<>();
        for (BundleFile file : assembler.captureFullPolicySet()) {
            byPath.put(file.path(), file);
        }
        for (Map.Entry<String, String> current :
                BundleContentReader.filesFrom(grounded.current().canonicalContent()).entrySet()) {
            ResourcePolicyIdentity.fromYaml(current.getValue())
                    .filter(identity -> identity.belongsToTenant(tenant))
                    .ifPresent(identity -> ResourcePolicyIdentity.putReplacing(
                            byPath, new BundleFile(current.getKey(), current.getValue())));
        }
        String tenantMarker = "@" + tenant;
        String authoredPath = "policies/" + parsed.resource() + tenantMarker + ".yaml";
        BundleFile authored = new BundleFile(authoredPath, yaml);
        ResourcePolicyIdentity.fromYaml(yaml).orElseThrow(
                () -> new IllegalStateException("canonical authored resource policy has no semantic identity"));
        ResourcePolicyIdentity.putReplacing(byPath, authored);
        List<BundleFile> files = new ArrayList<>(byPath.values());
        files.sort((a, b) -> a.path().compareTo(b.path()));
        return PolicyBundle.materialize(
                tenant,
                files,
                grounded.manifestRefs(),
                metadata,
                canonicalizer);
    }

}
