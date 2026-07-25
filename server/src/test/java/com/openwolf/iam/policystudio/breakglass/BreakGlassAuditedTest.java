package com.openwolf.iam.policystudio.breakglass;

import com.openwolf.iam.entity.AuditLog;
import com.openwolf.iam.policystudio.CanonicalPolicyWriter;
import com.openwolf.iam.policystudio.GeneratedPolicyValidator;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * C6.3 — a break-glass grant is fully audited to the tenant's A6 partition: the ISSUANCE (two-person
 * approved) AND EVERY USE land as {@code tenant_id}-scoped rows in {@code audit_log}, the same retained
 * partition tenant provisioning materialises. The records carry who requested, who approved, the scope,
 * the action, and the expiry — an emergency-access event is fully reconstructable.
 */
class BreakGlassAuditedTest {

    private final BreakGlassAuthoringService authoring = new BreakGlassAuthoringService(
            new BreakGlassValidator(60),
            new BreakGlassPolicyCompiler(),
            new GeneratedPolicyValidator(),
            new CanonicalPolicyWriter());

    @Test
    void grantAndUseFullyAudited() {
        PersistentBreakGlassAuditPartition partition =
                new PersistentBreakGlassAuditPartition(BreakGlassFixtures.auditRepo());
        BreakGlassApprovalService approvals = new BreakGlassApprovalService(partition);

        BreakGlassGrant grant = BreakGlassFixtures.grant("acme", 900, "alice");
        BreakGlassArtifact art = authoring.author(
                grant, BreakGlassFixtures.allowlist(), BreakGlassFixtures.request("acme"));
        assertThat(art.admissible()).isTrue();

        // 1. Issuance — two-person approved (author "alice", approver "carol"), audited.
        approvals.approveAndIssue(art, "alice", "carol", Set.of("policy_approver"), "corr-grant");

        // 2. Two uses of the active grant — each audited.
        approvals.recordUse(grant, "admin-p1", "register", "corr-use-1");
        approvals.recordUse(grant, "admin-p2", "register", "corr-use-2");

        List<AuditLog> records = partition.partition("acme");
        assertThat(records).hasSize(3);

        // The grant issuance record: who requested, who approved, the emergency surface.
        AuditLog granted = records.stream()
                .filter(r -> r.getAction().equals("break_glass.granted")).findFirst().orElseThrow();
        assertThat(granted.getTenantId()).isEqualTo("acme");
        assertThat(granted.getActorId()).isEqualTo("alice");            // requester
        assertThat(granted.getResourceId()).isEqualTo("acme");          // the scope
        assertThat(granted.getAfterState())
                .contains("\"approvedBy\":\"carol\"")
                .contains("\"action\":\"register\"")
                .contains("\"expiresAt\":\"" + grant.expiresAt() + "\"");

        // Both use records present, tenant-scoped, naming the principal + action.
        List<AuditLog> uses = records.stream()
                .filter(r -> r.getAction().equals("break_glass.used")).toList();
        assertThat(uses).hasSize(2);
        assertThat(uses).allSatisfy(u -> {
            assertThat(u.getTenantId()).isEqualTo("acme");
            assertThat(u.getResourceType()).isEqualTo("break_glass");
            assertThat(u.getAfterState()).contains("\"action\":\"register\"");
        });
        assertThat(uses).extracting(AuditLog::getActorId)
                .containsExactlyInAnyOrder("admin-p1", "admin-p2");
    }
}
