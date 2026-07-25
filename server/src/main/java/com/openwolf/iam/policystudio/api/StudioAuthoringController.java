package com.openwolf.iam.policystudio.api;

import com.openwolf.iam.policystudio.BaseCeiling;
import com.openwolf.iam.policystudio.ManifestVocabulary;
import com.openwolf.iam.policystudio.PolicyAuthoringRequest;
import com.openwolf.iam.policystudio.PlatformResourceKind;
import com.openwolf.iam.policystudio.PolicyStudioGenerationService;
import com.openwolf.iam.policystudio.StudioGenerationResult;
import com.openwolf.iam.policystudio.StudioGroundingProvider;
import com.openwolf.iam.policystudio.StudioGroundingSnapshot;
import com.openwolf.iam.policystudio.TenantScope;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.UUID;

/**
 * The C2 authoring surface — turn a natural-language intent into a validated, canonical Cerbos policy.
 * Thin over {@link PolicyStudioGenerationService}: the model proposes, the deterministic gate decides,
 * and only the IR-derived canonical YAML is ever returned (never the model's raw text). A bad proposal
 * is a normal {@code REJECTED} outcome with violations, not an error.
 *
 * <p><b>Tenant scope (author scope) is derived from the principal's {@code tenant_id} claim</b>, never a
 * body field: the controller builds {@code authorScope = TenantScope.of(<claim>)}, so a drafter cannot
 * author a policy targeting another tenant's subtree. Requires the {@code policy_author} role.
 *
 * <p><b>Trusted grounding only (Axiom S2).</b> The closed manifest {@code vocabulary} and the immutable
 * {@code baseCeiling} are <b>always derived server-side</b> for the principal's tenant via {@link
 * StudioGroundingProvider} — they are never accepted from the request body, so a caller cannot poison the
 * authoring gate with a widened vocabulary or a relaxed ceiling. The only caller inputs are the NL
 * {@code intent}, the {@code resourceKind} selector, and the {@code subscopesEnabled} flag.
 */
@RestController
@RequestMapping("/admin/studio")
@PreAuthorize("hasRole('policy_author')")
public class StudioAuthoringController {

    private final PolicyStudioGenerationService generation;
    private final ObjectProvider<StudioGroundingProvider> grounding;

    public StudioAuthoringController(PolicyStudioGenerationService generation,
                                     ObjectProvider<StudioGroundingProvider> grounding) {
        this.generation = generation;
        this.grounding = grounding;
    }

    /**
     * The draft request. {@code authorScope} is intentionally absent — it is derived from the principal —
     * and so are {@code vocabulary}/{@code baseCeiling}: those are server-derived grounding, never caller
     * input.
     */
    public record DraftPayload(String intent, String resourceKind, boolean subscopesEnabled) {}

    /** The deterministic-gate outcome the SPA renders. */
    public record Validation(boolean ok, List<String> violations, String stage) {}

    /** The draft response — a fresh id, the read-only canonical YAML, and the validation verdict. */
    public record DraftResponse(String draftId, String tenantId, String authorId,
                                boolean accepted, String canonicalYaml, Validation validation) {}

    /** {@code POST /admin/studio/drafts} — generate + validate a candidate policy from NL intent. */
    @PostMapping("/drafts")
    public ResponseEntity<DraftResponse> draft(@RequestBody DraftPayload payload, Authentication auth) {
        if (payload == null || payload.intent() == null) {
            throw new IllegalArgumentException("intent is required");
        }
        String author = StudioPrincipal.actor(auth);
        String tenant = StudioPrincipal.tenant(auth);
        String resourceKind = PlatformResourceKind.require(payload.resourceKind());

        // Grounding (vocabulary + immutable base ceiling) is ALWAYS server-derived for the principal's
        // tenant — never a body field — so a caller cannot widen the vocabulary or relax the ceiling.
        StudioGroundingProvider provider = grounding.getIfAvailable();
        if (provider == null) {
            throw new IllegalStateException("server manifest grounding is not available");
        }
        StudioGroundingSnapshot serverGrounding = provider.snapshot(tenant, resourceKind);
        ManifestVocabulary vocabulary = serverGrounding.vocabulary();
        BaseCeiling baseCeiling = serverGrounding.baseCeiling();

        // Author scope is the principal's own tenant — never a body field.
        TenantScope authorScope = TenantScope.of(tenant);
        PolicyAuthoringRequest request = new PolicyAuthoringRequest(
                payload.intent(), vocabulary, authorScope,
                payload.subscopesEnabled(), baseCeiling);

        StudioGenerationResult result = generation.generate(request);
        DraftResponse response = new DraftResponse(
                "draft-" + UUID.randomUUID(),
                tenant,
                author,
                result.accepted(),
                result.canonicalYaml(),
                new Validation(result.accepted(), result.violations(), result.stage().name()));
        return ResponseEntity.ok(response);
    }
}
