package com.openwolf.iam.policystudio.breakglass;

import com.openwolf.iam.entity.AuditLog;
import com.openwolf.iam.policystudio.BaseCeiling;
import com.openwolf.iam.policystudio.ManifestVocabulary;
import com.openwolf.iam.policystudio.PolicyAuthoringRequest;
import com.openwolf.iam.policystudio.TenantScope;
import com.openwolf.iam.repository.AuditLogRepository;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Set;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Deterministic fixtures for the C6 break-glass harness. Mirrors the C2 agent vocabulary + base
 * ceiling (so a compiled break-glass child is graded against the SAME contract every generated tenant
 * policy is) plus the approved break-glass allowlist and a grant builder. World B: none of these are
 * hardcoded domain literals in production Java — the tests feed the manifest shape directly.
 */
final class BreakGlassFixtures {

    private BreakGlassFixtures() {}

    static final String EMERGENCY_ACTION = "register";
    static final String EMERGENCY_ROLE = "platform_admin";
    static final String RESOURCE_KIND = "agent";

    static ManifestVocabulary vocab() {
        return new ManifestVocabulary(
                RESOURCE_KIND,
                Set.of("invoke", "invoke_membership", "register", "deregister"),
                Set.of("internal", "confidential", "confidential-pii"),
                Set.of("domain", "audience", "access_mode", "data_classification",
                        "segments", "admin_domains", "domains", "tenant_id"),
                Set.of("platform_admin", "domain_admin", "chat_user", "relationship_manager", "conduit_admin"),
                Set.of("business_derived_roles"));
    }

    /** Every base-allowed (action, role) tuple for {@code agent} (mirrors PolicyStudioFixtures). */
    static BaseCeiling ceiling() {
        return new BaseCeiling(
                RESOURCE_KIND,
                Set.of(
                        new BaseCeiling.Tuple("invoke", "platform_admin"),
                        new BaseCeiling.Tuple("invoke_membership", "platform_admin"),
                        new BaseCeiling.Tuple("register", "platform_admin"),
                        new BaseCeiling.Tuple("deregister", "platform_admin"),
                        new BaseCeiling.Tuple("invoke", "domain_admin"),
                        new BaseCeiling.Tuple("invoke_membership", "domain_admin"),
                        new BaseCeiling.Tuple("register", "domain_admin"),
                        new BaseCeiling.Tuple("deregister", "domain_admin"),
                        new BaseCeiling.Tuple("invoke", "chat_user"),
                        new BaseCeiling.Tuple("invoke", "relationship_manager"),
                        new BaseCeiling.Tuple("invoke_membership", "chat_user"),
                        new BaseCeiling.Tuple("invoke_membership", "relationship_manager")),
                true,
                Set.of("agent@"));
    }

    /** Approved emergency surface: the {@code agent} resource, the {@code register} action only. */
    static BreakGlassAllowlist allowlist() {
        return new BreakGlassAllowlist(Set.of(RESOURCE_KIND), Set.of(EMERGENCY_ACTION));
    }

    static PolicyAuthoringRequest request(String authorScope) {
        return new PolicyAuthoringRequest(
                "break-glass emergency access", vocab(), TenantScope.of(authorScope), false, ceiling());
    }

    /** A well-formed grant of the emergency action, expiring {@code ttlSeconds} after now. */
    static BreakGlassGrant grant(String scope, long ttlSeconds, String requestedBy) {
        Instant now = Instant.now();
        return new BreakGlassGrant(
                TenantScope.of(scope), RESOURCE_KIND, EMERGENCY_ACTION, EMERGENCY_ROLE,
                now, now.plusSeconds(ttlSeconds),
                "emergency incident #4711 — restore admin registration", requestedBy);
    }

    /** A grant with an explicit issued/expiry window (for bounds tests). */
    static BreakGlassGrant grant(String scope, Instant issuedAt, Instant expiresAt, String requestedBy) {
        return new BreakGlassGrant(
                TenantScope.of(scope), RESOURCE_KIND, EMERGENCY_ACTION, EMERGENCY_ROLE,
                issuedAt, expiresAt, "emergency incident #4711", requestedBy);
    }

    /** A stateful in-memory {@link AuditLogRepository} (mirrors ProvisioningTestSupport.auditRepo()). */
    static AuditLogRepository auditRepo() {
        List<AuditLog> logs = Collections.synchronizedList(new ArrayList<>());
        AuditLogRepository repo = mock(AuditLogRepository.class);
        when(repo.save(any(AuditLog.class))).thenAnswer(a -> {
            AuditLog l = a.getArgument(0);
            logs.add(l);
            return l;
        });
        when(repo.saveAndFlush(any(AuditLog.class))).thenAnswer(a -> {
            AuditLog l = a.getArgument(0);
            logs.add(l);
            return l;
        });
        when(repo.findByTenantIdOrderByOccurredAtDesc(anyString())).thenAnswer(a -> logs.stream()
                .filter(l -> l.getTenantId().equals(a.<String>getArgument(0)))
                .toList());
        return repo;
    }
}
