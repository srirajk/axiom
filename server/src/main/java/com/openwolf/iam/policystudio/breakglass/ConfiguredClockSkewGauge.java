package com.openwolf.iam.policystudio.breakglass;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.time.Duration;

/**
 * Default {@link ClockSkewGauge} (Axiom Story C6.5). Reports the deployment-declared assumed skew
 * ({@code iam.break-glass.assumed-clock-skew-millis}, default 0). In production this bean is replaced
 * by an NTP/chrony-backed gauge — measuring true skew is an operational concern, not app logic (see
 * the documented clock-sync SLO). Kept as a bean so readiness always has a source to gate on.
 */
@Component
public class ConfiguredClockSkewGauge implements ClockSkewGauge {

    private final Duration assumedSkew;

    public ConfiguredClockSkewGauge(
            @Value("${iam.break-glass.assumed-clock-skew-millis:0}") long assumedSkewMillis) {
        this.assumedSkew = Duration.ofMillis(Math.abs(assumedSkewMillis));
    }

    @Override
    public Duration measuredSkew() {
        return assumedSkew;
    }
}
