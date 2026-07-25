package com.openwolf.iam.policystudio.breakglass;

import com.openwolf.iam.policystudio.TenantScope;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * C6.5 — the deterministic BOUNDS gate rejects an out-of-policy break-glass grant BEFORE any YAML is
 * compiled or promoted: a TTL over the 60-minute maximum, a wildcard action/role, a malformed expiry
 * (expiresAt ≤ issuedAt), or an off-allowlist action/resource. Plus the clock-sync SLO readiness gate:
 * a host whose skew exceeds the SLO reports DOWN, because a drifted clock could honour an expired grant.
 */
class BreakGlassBoundsTest {

    private final BreakGlassValidator validator = new BreakGlassValidator(60);

    @Test
    void wellFormedGrantIsAccepted() {
        BreakGlassGrant g = BreakGlassFixtures.grant("acme", 900, "alice");
        assertThat(validator.validate(g, BreakGlassFixtures.allowlist(), BreakGlassFixtures.vocab()).accepted())
                .isTrue();
    }

    @Test
    void ttlOver60MinutesIsRejected() {
        Instant now = Instant.now();
        BreakGlassGrant g = BreakGlassFixtures.grant("acme", now, now.plus(Duration.ofMinutes(61)), "alice");
        BreakGlassValidator.Result r =
                validator.validate(g, BreakGlassFixtures.allowlist(), BreakGlassFixtures.vocab());
        assertThat(r.accepted()).isFalse();
        assertThat(r.violations()).anySatisfy(x -> assertThat(x).contains("exceeds the maximum"));
    }

    @Test
    void malformedExpiryIsRejected() {
        Instant now = Instant.now();
        // expiresAt BEFORE issuedAt — a grant that expires before it begins.
        BreakGlassGrant g = BreakGlassFixtures.grant("acme", now, now.minusSeconds(30), "alice");
        BreakGlassValidator.Result r =
                validator.validate(g, BreakGlassFixtures.allowlist(), BreakGlassFixtures.vocab());
        assertThat(r.accepted()).isFalse();
        assertThat(r.violations()).anySatisfy(x -> assertThat(x).contains("must be strictly after issuedAt"));
    }

    @Test
    void wildcardActionAndRoleAreRejected() {
        Instant now = Instant.now();
        BreakGlassGrant g = new BreakGlassGrant(
                TenantScope.of("acme"), "agent", "*", "*", now, now.plusSeconds(600), "why", "alice");
        BreakGlassValidator.Result r =
                validator.validate(g, BreakGlassFixtures.allowlist(), BreakGlassFixtures.vocab());
        assertThat(r.accepted()).isFalse();
        assertThat(r.violations()).anySatisfy(x -> assertThat(x).contains("never a wildcard"));
    }

    @Test
    void offAllowlistActionIsRejected() {
        Instant now = Instant.now();
        // deregister is a real vocabulary action but NOT on the approved break-glass allowlist.
        BreakGlassGrant g = new BreakGlassGrant(
                TenantScope.of("acme"), "agent", "deregister", "platform_admin",
                now, now.plusSeconds(600), "why", "alice");
        BreakGlassValidator.Result r =
                validator.validate(g, BreakGlassFixtures.allowlist(), BreakGlassFixtures.vocab());
        assertThat(r.accepted()).isFalse();
        assertThat(r.violations()).anySatisfy(x -> assertThat(x).contains("not an approved break-glass action"));
    }

    @Test
    void offAllowlistResourceIsRejected() {
        Instant now = Instant.now();
        BreakGlassAllowlist onlyOtherResource = new BreakGlassAllowlist(
                java.util.Set.of("other-kind"), java.util.Set.of("register"));
        BreakGlassGrant g = BreakGlassFixtures.grant("acme", now, now.plusSeconds(600), "alice");
        BreakGlassValidator.Result r =
                validator.validate(g, onlyOtherResource, BreakGlassFixtures.vocab());
        assertThat(r.accepted()).isFalse();
        assertThat(r.violations()).anySatisfy(x -> assertThat(x).contains("not an approved break-glass resource"));
    }

    @Test
    void clockReadinessDownWhenSkewExceedsSlo() {
        // SLO 5s. Within bound → UP; beyond bound → DOWN (an expired grant could be wrongly honoured).
        BreakGlassClockReadiness within = new BreakGlassClockReadiness(() -> Duration.ofSeconds(3), 5);
        BreakGlassClockReadiness beyond = new BreakGlassClockReadiness(() -> Duration.ofSeconds(9), 5);

        assertThat(within.withinSlo()).isTrue();
        assertThat(within.health().getStatus().getCode()).isEqualTo("UP");

        assertThat(beyond.withinSlo()).isFalse();
        assertThat(beyond.health().getStatus().getCode()).isEqualTo("DOWN");
        assertThat(beyond.health().getDetails()).containsEntry("sloMillis", 5000L);
    }
}
