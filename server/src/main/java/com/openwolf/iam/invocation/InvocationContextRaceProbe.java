package com.openwolf.iam.invocation;

import java.util.UUID;

/**
 * Optional observation point for concurrency tests (no implementation exists in production code). It is called inside
 * the database transaction at the named point, after the serializing root lock is held, so a test can hold one
 * transaction open there and drive a competing one deterministically.
 */
public interface InvocationContextRaceProbe {
    String BRANCH_INSERTED = "branch-inserted";
    String REVOKE_LOCKED = "revoke-locked";

    void reached(String point, UUID contextId);
}
