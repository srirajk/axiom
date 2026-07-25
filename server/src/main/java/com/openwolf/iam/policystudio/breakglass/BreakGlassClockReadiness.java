package com.openwolf.iam.policystudio.breakglass;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.actuate.health.Health;
import org.springframework.boot.actuate.health.HealthIndicator;
import org.springframework.stereotype.Component;

import java.time.Duration;

/**
 * Readiness gate on the break-glass clock-sync SLO (Axiom Story C6.5). A break-glass grant self-
 * expires on {@code now()} evaluated inside the PDP, so a host whose clock has drifted outside the
 * documented SLO ({@code iam.break-glass.clock-skew-slo-seconds}, default 5s) could honour an expired
 * grant. This {@link HealthIndicator} reports DOWN when the measured skew exceeds the SLO, so the
 * host is pulled from readiness rather than silently enforcing an unreliable time bound.
 *
 * <p>Registered under the health name {@code breakGlassClock}; contributes to the actuator readiness
 * group. The skew source is {@link ClockSkewGauge} (NTP/chrony in production; a fixed value in tests).
 */
@Component("breakGlassClock")
public class BreakGlassClockReadiness implements HealthIndicator {

    private final ClockSkewGauge gauge;
    private final Duration slo;

    public BreakGlassClockReadiness(
            ClockSkewGauge gauge,
            @Value("${iam.break-glass.clock-skew-slo-seconds:5}") long sloSeconds) {
        this.gauge = gauge;
        this.slo = Duration.ofSeconds(sloSeconds);
    }

    /** The configured clock-sync SLO (default 5s). */
    public Duration slo() {
        return slo;
    }

    /** True iff the current measured skew is within the SLO. */
    public boolean withinSlo() {
        return gauge.measuredSkew().abs().compareTo(slo) <= 0;
    }

    @Override
    public Health health() {
        Duration skew = gauge.measuredSkew().abs();
        Health.Builder b = withinSlo() ? Health.up() : Health.down();
        return b.withDetail("measuredSkewMillis", skew.toMillis())
                .withDetail("sloMillis", slo.toMillis())
                .withDetail("reason", withinSlo()
                        ? "clock within break-glass SLO"
                        : "clock skew exceeds break-glass SLO — an expired grant may be wrongly honoured")
                .build();
    }
}
