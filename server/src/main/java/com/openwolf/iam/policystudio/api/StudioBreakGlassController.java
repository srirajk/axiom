package com.openwolf.iam.policystudio.api;

import com.openwolf.iam.policystudio.PolicyAuthoringRequest;
import com.openwolf.iam.policystudio.TenantScope;
import com.openwolf.iam.policystudio.breakglass.BreakGlassArtifact;
import com.openwolf.iam.policystudio.breakglass.BreakGlassApprovalService;
import com.openwolf.iam.policystudio.breakglass.BreakGlassAuthoringService;
import com.openwolf.iam.policystudio.breakglass.BreakGlassGrant;
import com.openwolf.iam.policystudio.breakglass.BreakGlassIssuanceService;
import com.openwolf.iam.policystudio.breakglass.BreakGlassTrustRootProvider;
import com.fasterxml.jackson.databind.JsonNode;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Set;
import java.util.UUID;

/**
 * The C6 break-glass surface — a time-bounded emergency grant that is a normal scoped policy whose ALLOW
 * carries a {@code now() < timestamp(expiresAt)} CEL condition, so enforcement self-limits inside the PDP.
 *
 * <p>Two-person by construction (C6.4 / C1.2):
 * <ol>
 *   <li>{@code POST /admin/studio/break-glass} — a <b>drafter</b> authors the grant. The same two
 *       deterministic gates every studio policy runs (C6 bounds + the C2 policy gate) produce a
 *       {@link BreakGlassArtifact}; only an admissible one can proceed. The requester is the principal.</li>
 *   <li>{@code POST /admin/studio/break-glass/{grantId}/approve} — a different <b>approver</b> issues it.
 *       {@link BreakGlassApprovalService} enforces requester≠approver and the configured approver role
 *       server-side (a superuser is never an auto-approver).</li>
 * </ol>
 *
 * <p><b>Tenant scope</b> is the principal's {@code tenant_id} claim; the grant's scope root must equal it,
 * so a grant can never target another tenant. (The compiled artifact is additionally structurally unable
 * to name another tenant via C2 segment-wise scope containment.)
 */
@RestController
@RequestMapping("/admin/studio/break-glass")
public class StudioBreakGlassController {

    private final BreakGlassAuthoringService authoring;
    private final BreakGlassIssuanceService issuance;
    private final BreakGlassTrustRootProvider trustRoots;
    private final StudioSessionStore store;

    public StudioBreakGlassController(BreakGlassAuthoringService authoring,
                                      BreakGlassIssuanceService issuance,
                                      BreakGlassTrustRootProvider trustRoots,
                                      StudioSessionStore store) {
        this.authoring = authoring;
        this.issuance = issuance;
        this.trustRoots = trustRoots;
        this.store = store;
    }

    /** The request to author a break-glass grant. {@code scope} must be within the principal's tenant. */
    public record RequestPayload(String scope, String resourceKind, String action, String role,
                                 long ttlMinutes, String justification,
                                 JsonNode vocabulary, JsonNode baseCeiling, JsonNode allowlist) {}

    /** The authoring outcome: the pending grant id, whether it is admissible, and any gate violations. */
    public record GrantView(String grantId, String tenantId, String requestedBy, boolean admissible,
                            boolean issued, Instant expiresAt,
                            List<String> boundsViolations, List<String> c2Violations) {
        static GrantView pending(StudioSessionStore.PendingGrant g) {
            BreakGlassArtifact a = g.artifact();
            return new GrantView(g.grantId(), g.tenantId(), g.requestedBy(), a.admissible(), g.issued(),
                    a.grant().expiresAt(), a.boundsResult().violations(), a.c2Result().violations());
        }
    }

    /** {@code POST /admin/studio/break-glass} — author (request) a time-bounded grant. Drafter only. */
    @PostMapping
    @PreAuthorize("hasRole('policy_author')")
    public ResponseEntity<GrantView> request(@RequestBody RequestPayload payload, Authentication auth) {
        if (payload == null || payload.scope() == null || payload.resourceKind() == null) {
            throw new IllegalArgumentException("scope and resourceKind are required");
        }
        // These fields existed on the original API. Reject them explicitly instead of silently ignoring
        // them, so no client can mistake caller-authored boundaries for trusted server policy.
        if (payload.vocabulary() != null || payload.baseCeiling() != null || payload.allowlist() != null) {
            throw new IllegalArgumentException("vocabulary, baseCeiling and allowlist are server-owned "
                    + "trust roots and must not be supplied by the caller");
        }
        String requester = StudioPrincipal.actor(auth);
        String tenant = StudioPrincipal.tenant(auth);

        // Server-clock TTL clamp (defence in depth): the grant window is stamped from the SERVER now() and
        // must be a positive span of at most 60 minutes. issuedAt is ALWAYS server now() — any caller
        // issuedAt is ignored (there is no such field) — so a future-dated issuedAt cannot widen the
        // window past the server clock. (The C6 bounds gate also checks the span; this makes it robust.)
        long ttl = payload.ttlMinutes();
        if (ttl <= 0 || ttl > 60) {
            throw new IllegalArgumentException(
                    "ttlMinutes must be within (0, 60] against the server clock — was " + ttl);
        }
        // issuedAt is stamped from the SERVER clock inside the factory; there is no caller issuedAt to
        // ignore, and expiresAt = issuedAt + ttl (H1). The bounds gate re-validates against the server clock.
        BreakGlassGrant grant = BreakGlassGrant.issue(
                Clock.systemUTC(), TenantScope.of(payload.scope()), payload.resourceKind(),
                payload.action(), payload.role(), Duration.ofMinutes(ttl), payload.justification(), requester);

        // Cross-tenant guard: the grant's scope root must be the principal's own tenant.
        StudioPrincipal.assertSameTenant(tenant, grant.tenantId());

        BreakGlassTrustRootProvider.TrustRoots roots = trustRoots.resolve(tenant, payload.resourceKind());

        PolicyAuthoringRequest request = new PolicyAuthoringRequest(
                "break-glass emergency grant", roots.vocabulary(), TenantScope.of(tenant),
                false, roots.baseCeiling());
        BreakGlassArtifact artifact = authoring.author(grant, roots.allowlist(), request);

        StudioSessionStore.PendingGrant pending = store.putGrant(tenant, requester, artifact);
        return ResponseEntity.ok(GrantView.pending(pending));
    }

    /**
     * {@code POST /admin/studio/break-glass/{grantId}/approve} — the two-person issue step. Approver only;
     * the service rejects self-approval (requester≠approver) and a missing approver role.
     *
     * <p><b>S4 — the grant now actually enforces.</b> After the C6 two-person gate passes, the grant is
     * MERGED into the tenant's current active bundle and PROMOTED through C5
     * ({@link BreakGlassPromotionService}), so it loads into the serving PDP (S1). The {@code issued} flag
     * is set only once that promotion succeeds — a failed promotion fails closed and leaves the grant
     * unissued. The emergency ALLOW is additive (normal grants are preserved) and self-limits inside the
     * PDP at {@code expiresAt}.
     */
    @PostMapping("/{grantId}/approve")
    @PreAuthorize("hasRole('" + BreakGlassApprovalService.APPROVER_ROLE + "')")
    public ResponseEntity<GrantView> approve(@PathVariable String grantId,
                                             @RequestHeader(value = "X-Correlation-Id", required = false) String correlationId,
                                             Authentication auth) {
        String approver = StudioPrincipal.actor(auth);
        String tenant = StudioPrincipal.tenant(auth);
        Set<String> approverRoles = StudioPrincipal.roles(auth);

        StudioSessionStore.PendingGrant pending = store.getGrant(tenant, grantId)
                .orElseThrow(() -> new IllegalArgumentException("no pending break-glass grant '" + grantId + "'"));
        if (!pending.artifact().grant().expiresAt().isAfter(Instant.now())) {
            throw new IllegalStateException("break-glass grant '" + grantId + "' is expired and cannot be issued");
        }

        String correlation = correlationId != null ? correlationId : UUID.randomUUID().toString();
        // (1) C6 two-person gate. SoD is keyed on the VERIFIED author identity captured at author
        //     time (pending.requestedBy(), set from the authenticated sub) — not grant.requestedBy() (a
        //     caller field on the grant). (H1)
        // (2) Durable PENDING→ACTIVATED issuance/outbox: promotion is idempotent, and GRANTED is appended
        // only after activation. An audit outage leaves a reconcilable ACTIVATED row rather than ambiguity.
        issuance.issue(pending, approver, approverRoles, correlation);
        store.markIssued(pending);
        return store.getGrant(tenant, grantId).map(GrantView::pending).map(ResponseEntity::ok)
                .orElseGet(() -> ResponseEntity.notFound().build());
    }

    /** {@code GET /admin/studio/break-glass} — pending requests plus active grants for this tenant. */
    @GetMapping
    @PreAuthorize("hasAnyRole('policy_author','policy_approver','platform_admin')")
    public ResponseEntity<List<GrantView>> active(Authentication auth) {
        String tenant = StudioPrincipal.tenant(auth);
        List<GrantView> active = store.visibleGrants(tenant).stream().map(GrantView::pending).toList();
        return ResponseEntity.ok(active);
    }
}
