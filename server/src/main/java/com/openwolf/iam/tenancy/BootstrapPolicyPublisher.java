package com.openwolf.iam.tenancy;

import com.openwolf.iam.policystudio.lifecycle.PolicyBundle;

/** Publishes and durably records a bootstrap bundle before B4 makes its tenant visible. */
@FunctionalInterface
public interface BootstrapPolicyPublisher {

    /** Fail closed unless the exact bundle is serving-ready and durably joinable by its {@code b_*} id. */
    void publishAndPersist(PolicyBundle bundle);
}
