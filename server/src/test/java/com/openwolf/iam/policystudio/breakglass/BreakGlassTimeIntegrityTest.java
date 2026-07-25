package com.openwolf.iam.policystudio.breakglass;

import com.openwolf.iam.policystudio.CanonicalPolicyWriter;
import com.openwolf.iam.policystudio.GeneratedPolicyValidator;
import com.openwolf.iam.policystudio.PolicyIR;
import com.openwolf.iam.policystudio.TenantScope;
import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.temporal.ChronoUnit;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * H1 — break-glass TIME INTEGRITY. The window is bound to the SERVER clock, not to a caller-supplied
 * {@code issuedAt}/relative span, on all three planes:
 *
 * <ul>
 *   <li><b>Bounds gate</b> ({@link BreakGlassValidator}) validates {@code issuedAt ≤ now} and
 *       {@code expiresAt ∈ (now, now+60m]} against a fixed server {@link Clock} — so a future-dated
 *       {@code issuedAt} with an otherwise-legal 30-minute span (which span-only checks accepted,
 *       keeping the grant hot for weeks) is REJECTED.</li>
 *   <li><b>Compiler</b> ({@link BreakGlassPolicyCompiler}) bakes BOTH the lower bound
 *       {@code now() >= timestamp(issuedAt)} and the upper bound {@code now() < timestamp(expiresAt)}
 *       into the ALLOW, plus the complementary DENY — so a future-dated grant is inert in the PDP.</li>
 *   <li><b>Two-person gate</b> ({@link BreakGlassApprovalService}) keys separation of duties on the
 *       VERIFIED author/approver identities passed from the caller context, and fails CLOSED on a
 *       {@code null} approver identity (never skips the self-approval check).</li>
 * </ul>
 *
 * A pure JUnit gate test — no Docker, runs under surefire.
 */
class BreakGlassTimeIntegrityTest {

    private static final Instant NOW = Instant.parse("2026-07-17T12:00:00Z");
    private final Clock serverClock = Clock.fixed(NOW, ZoneOffset.UTC);
    private final BreakGlassValidator validator = new BreakGlassValidator(60, serverClock);

    private BreakGlassGrant serverStamped(Duration ttl, String requestedBy) {
        return BreakGlassGrant.issue(serverClock, TenantScope.of("acme"),
                BreakGlassFixtures.RESOURCE_KIND, BreakGlassFixtures.EMERGENCY_ACTION,
                BreakGlassFixtures.EMERGENCY_ROLE, ttl, "emergency incident #4711", requestedBy);
    }

    // ── server-clock window ────────────────────────────────────────────────────────────────────

    @Test
    void futureDatedIssuedAtIsRejectedAgainstServerClock() {
        // Issued a MONTH ahead with a legal 30-minute SPAN — span-only would ACCEPT (keeping a
        // "60-min" grant hot for weeks). The server clock rejects both the future issuedAt and the
        // beyond-ceiling expiry.
        Instant future = NOW.plus(Duration.ofDays(30));
        BreakGlassGrant g = BreakGlassFixtures.grant("acme", future, future.plus(Duration.ofMinutes(30)), "alice");

        BreakGlassValidator.Result r =
                validator.validate(g, BreakGlassFixtures.allowlist(), BreakGlassFixtures.vocab());

        assertThat(r.accepted()).isFalse();
        assertThat(r.violations()).anySatisfy(v -> assertThat(v).contains("in the future"));
        assertThat(r.violations()).anySatisfy(v -> assertThat(v).contains("beyond the maximum"));
    }

    @Test
    void expiresAtBeyondSixtyMinutesFromServerClockIsRejected() {
        BreakGlassGrant g = BreakGlassFixtures.grant("acme", NOW, NOW.plus(Duration.ofMinutes(61)), "alice");

        BreakGlassValidator.Result r =
                validator.validate(g, BreakGlassFixtures.allowlist(), BreakGlassFixtures.vocab());

        assertThat(r.accepted()).isFalse();
        assertThat(r.violations()).anySatisfy(v -> assertThat(v).contains("beyond the maximum"));
    }

    @Test
    void serverStampedGrantWithinWindowIsAccepted() {
        BreakGlassGrant g = serverStamped(Duration.ofMinutes(15), "alice");
        // issuedAt is stamped from the server clock — never a caller value.
        assertThat(g.issuedAt()).isEqualTo(NOW);
        assertThat(validator.validate(g, BreakGlassFixtures.allowlist(), BreakGlassFixtures.vocab()).accepted())
                .isTrue();
    }

    // ── compiler carries BOTH CEL bounds ───────────────────────────────────────────────────────

    @Test
    void compiledPolicyCarriesBothCelBounds() {
        BreakGlassGrant g = serverStamped(Duration.ofMinutes(15), "alice");
        PolicyIR ir = new BreakGlassPolicyCompiler().compile(g, BreakGlassFixtures.ceiling());

        String issued = g.issuedAt().truncatedTo(ChronoUnit.SECONDS).toString();
        String expires = g.expiresAt().truncatedTo(ChronoUnit.SECONDS).toString();

        PolicyIR.Rule allow = ir.rules().stream()
                .filter(r -> r.isAllow() && r.actions().contains(BreakGlassFixtures.EMERGENCY_ACTION))
                .findFirst().orElseThrow();
        String allowExpr = allow.conditionText();
        // BOTH bounds present in the ALLOW window: the lower bound (issuedAt) AND the upper bound (expiresAt).
        assertThat(allowExpr).contains("now() >= timestamp(\"" + issued + "\")");
        assertThat(allowExpr).contains("now() < timestamp(\"" + expires + "\")");

        // The complementary DENY fires OUTSIDE the window — carrying the lower-bound negation too, so a
        // future-dated grant is inert (denied) in the PDP.
        PolicyIR.Rule deny = ir.rules().stream()
                .filter(r -> !r.isAllow() && r.actions().contains(BreakGlassFixtures.EMERGENCY_ACTION)
                        && r.conditionText() != null && !r.conditionText().isBlank())
                .findFirst().orElseThrow();
        String denyExpr = deny.conditionText();
        assertThat(denyExpr).contains("now() < timestamp(\"" + issued + "\")");
        assertThat(denyExpr).contains("now() >= timestamp(\"" + expires + "\")");
    }

    // ── two-person SoD over VERIFIED identity ──────────────────────────────────────────────────

    private BreakGlassApprovalService approvals() {
        return new BreakGlassApprovalService(
                new PersistentBreakGlassAuditPartition(BreakGlassFixtures.auditRepo()));
    }

    private BreakGlassArtifact admissibleArtifact(String author) {
        BreakGlassAuthoringService authoring = new BreakGlassAuthoringService(
                validator, new BreakGlassPolicyCompiler(), new GeneratedPolicyValidator(),
                new CanonicalPolicyWriter());
        BreakGlassArtifact art = authoring.author(
                serverStamped(Duration.ofMinutes(15), author),
                BreakGlassFixtures.allowlist(), BreakGlassFixtures.request("acme"));
        assertThat(art.admissible()).isTrue();
        return art;
    }

    @Test
    void authorEqualsApproverRejectedViaVerifiedIdentity() {
        assertThatThrownBy(() -> approvals().approveAndIssue(
                admissibleArtifact("alice"), "alice", "alice", Set.of("policy_approver"), "corr"))
                .isInstanceOf(BreakGlassSodException.class)
                .hasMessageContaining("author≠approver");
    }

    @Test
    void nullApproverIdentityFailsClosed() {
        // A null approver must DENY (fail closed), never skip the self-approval check.
        assertThatThrownBy(() -> approvals().approveAndIssue(
                admissibleArtifact("alice"), "alice", null, Set.of("policy_approver"), "corr"))
                .isInstanceOf(BreakGlassSodException.class)
                .hasMessageContaining("approver identity is required");
    }
}
