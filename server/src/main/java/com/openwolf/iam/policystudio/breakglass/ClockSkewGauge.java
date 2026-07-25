package com.openwolf.iam.policystudio.breakglass;

import java.time.Duration;

/**
 * The measured wall-clock skew of this PDP host against trusted time (Axiom Story C6.5). Because a
 * break-glass grant self-expires on {@code now()} evaluated INSIDE the PDP, the security of the time
 * bound is only as good as the host's clock: a host whose clock runs slow could honour an expired
 * grant. This port abstracts the skew measurement so readiness can gate on it.
 *
 * <p>The real production wiring measures skew against an NTP/chrony source — an OPERATIONAL concern,
 * deferred to the deployment (documented SLO, not app logic). The default bean reports a configured
 * assumed skew; tests inject a precise value to exercise the readiness boundary.
 */
@FunctionalInterface
public interface ClockSkewGauge {

    /** The current absolute clock skew estimate for this host (never null). */
    Duration measuredSkew();
}
