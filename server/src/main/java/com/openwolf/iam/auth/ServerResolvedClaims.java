package com.openwolf.iam.auth;

import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * Implemented by Phase 3 grant authentications whose every claim Axiom has already resolved from durable state
 * (standing grants, approved actions, workload federation). The token customizer emits exactly these claims and
 * binds an Axiom session; nothing is taken from the request.
 */
public interface ServerResolvedClaims {
    String subject();

    List<String> audience();

    Map<String, Object> claims();

    String sessionTenantId();

    UUID sessionApplicationId();

    /** Whether the session belongs to a workforce principal (re-checked on every session-bound use). */
    boolean workforceSession();
}
