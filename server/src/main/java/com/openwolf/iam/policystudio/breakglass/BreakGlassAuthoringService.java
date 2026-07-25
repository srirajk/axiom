package com.openwolf.iam.policystudio.breakglass;

import com.openwolf.iam.policystudio.CanonicalPolicyWriter;
import com.openwolf.iam.policystudio.GeneratedPolicyValidator;
import com.openwolf.iam.policystudio.PolicyAuthoringRequest;
import com.openwolf.iam.policystudio.PolicyIR;
import org.springframework.stereotype.Service;

/**
 * The expedited authoring path for a break-glass grant (Axiom Story C6). "Expedited" means faster,
 * NOT looser: it runs the SAME two deterministic gates every studio policy runs, in order —
 *
 * <ol>
 *   <li><b>C6 bounds</b> ({@link BreakGlassValidator}) — positive/≤60m TTL, approved action/resource
 *       allowlist, no wildcard, tenant-scoped, justified. Runs BEFORE any YAML is emitted.</li>
 *   <li><b>Compile</b> ({@link BreakGlassPolicyCompiler}) — lower the grant into a tenant-scoped
 *       restriction child whose granted tuple carries the {@code now() < timestamp(expiresAt)} pair.</li>
 *   <li><b>C2 policy gate</b> ({@link GeneratedPolicyValidator}) — the same shape / segment-wise
 *       scope containment / grounding / no-wildcard / totality gate every generated tenant policy
 *       passes. A grant naming another tenant is rejected here at the scope check.</li>
 * </ol>
 *
 * The result is a {@link BreakGlassArtifact}; only an {@link BreakGlassArtifact#admissible()} one can
 * proceed to two-person approval ({@code BreakGlassApprovalService}). Nothing here mutates a live
 * bundle — authoring is on the studio (control) plane; enforcement is the PDP's alone.
 */
@Service
public class BreakGlassAuthoringService {

    private final BreakGlassValidator boundsGate;
    private final BreakGlassPolicyCompiler compiler;
    private final GeneratedPolicyValidator policyGate;
    private final CanonicalPolicyWriter writer;

    public BreakGlassAuthoringService(BreakGlassValidator boundsGate,
                                      BreakGlassPolicyCompiler compiler,
                                      GeneratedPolicyValidator policyGate,
                                      CanonicalPolicyWriter writer) {
        this.boundsGate = boundsGate;
        this.compiler = compiler;
        this.policyGate = policyGate;
        this.writer = writer;
    }

    public BreakGlassArtifact author(BreakGlassGrant grant,
                                     BreakGlassAllowlist allowlist,
                                     PolicyAuthoringRequest request) {
        BreakGlassValidator.Result bounds = boundsGate.validate(grant, allowlist, request.vocabulary());

        PolicyIR ir = compiler.compile(grant, request.baseCeiling());
        String yaml = writer.write(ir);

        // Even if bounds failed we still run C2 so the artifact carries the full picture; the
        // artifact is admissible only when BOTH gates accept.
        GeneratedPolicyValidator.Result c2 = policyGate.validate(ir, request);

        return new BreakGlassArtifact(grant, ir, yaml, bounds, c2);
    }
}
