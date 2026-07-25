package com.openwolf.iam.policystudio.breakglass;

import com.openwolf.iam.policystudio.TenantScope;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;

/**
 * An emergency (break-glass) access grant (Axiom Story C6).
 *
 * <p>The whole point of break-glass in this system: it is a <b>normal scoped policy grant whose
 * ALLOW carries a CEL time condition</b> ({@code now() < timestamp(expiresAt)}). Enforcement is
 * therefore self-limiting <em>inside the PDP</em> — nothing external revokes it. Because Cerbos
 * evaluates the condition on every {@code CheckResources}, an expired grant DENIES even if the
 * control plane / studio is down (Cerbos is Apache-2.0 and air-gap-ready). This record is the
 * typed request; {@link BreakGlassPolicyCompiler} lowers it into a validated, tenant-scoped Cerbos
 * restriction child whose granted tuple carries the time condition.
 *
 * <p>Tenant safety: {@code scope} is a full Cerbos {@link TenantScope}; the compiled artifact is
 * structurally unable to name another tenant (C2's segment-wise scope containment is re-checked on
 * the compiled IR). The audit partition (A6) is keyed by {@link #tenantId()} — the tenant root of
 * the scope.
 *
 * @param scope        the exact tenant scope the emergency access is granted at (never root)
 * @param resourceKind the Cerbos resource kind (must be an approved break-glass resource)
 * @param action       the single emergency action (must be an approved break-glass action, never {@code "*"})
 * @param role         the principal role that receives the time-boxed grant (never {@code "*"})
 * @param issuedAt     when the grant was issued
 * @param expiresAt    when the grant self-expires — the timestamp baked into the CEL condition
 * @param justification the human reason the emergency access was requested (audited)
 * @param requestedBy  the requester / last editor of the grant (the SoD "author" — never the approver)
 */
public record BreakGlassGrant(
        TenantScope scope,
        String resourceKind,
        String action,
        String role,
        Instant issuedAt,
        Instant expiresAt,
        String justification,
        String requestedBy) {

    public BreakGlassGrant {
        if (scope == null) {
            throw new IllegalArgumentException("scope must be set");
        }
        if (resourceKind == null || resourceKind.isBlank()) {
            throw new IllegalArgumentException("resourceKind must be set");
        }
        if (action == null || action.isBlank()) {
            throw new IllegalArgumentException("action must be set");
        }
        if (role == null || role.isBlank()) {
            throw new IllegalArgumentException("role must be set");
        }
        if (issuedAt == null || expiresAt == null) {
            throw new IllegalArgumentException("issuedAt and expiresAt must be set");
        }
        if (requestedBy == null || requestedBy.isBlank()) {
            throw new IllegalArgumentException("requestedBy (the SoD author) must be set");
        }
    }

    /**
     * Mint a grant stamped from the SERVER clock (H1): {@code issuedAt = clock.instant()} and
     * {@code expiresAt = issuedAt + ttl}. This is the ONLY sanctioned way to create a grant on the
     * request path — there is no way to smuggle a caller-supplied {@code issuedAt} through it, so a
     * future-dated {@code issuedAt} can never widen the window past the server clock. The bounds gate
     * ({@link BreakGlassValidator}) additionally re-validates the window against the server clock, and
     * the compiler bakes {@code now() >= timestamp(issuedAt)} into the PDP rule, so a future-dated
     * grant is inert in all three planes.
     */
    public static BreakGlassGrant issue(Clock clock, TenantScope scope, String resourceKind,
                                        String action, String role, Duration ttl,
                                        String justification, String requestedBy) {
        if (clock == null) {
            throw new IllegalArgumentException("clock must be set (issuedAt is stamped server-side)");
        }
        if (ttl == null || ttl.isZero() || ttl.isNegative()) {
            throw new IllegalArgumentException("ttl must be a positive duration — was " + ttl);
        }
        Instant now = clock.instant();
        return new BreakGlassGrant(scope, resourceKind, action, role, now, now.plus(ttl),
                justification, requestedBy);
    }

    /** The tenant partition key (A6): the tenant root of the scope. */
    public String tenantId() {
        return scope.isRoot() ? "" : scope.segments().get(0);
    }
}
