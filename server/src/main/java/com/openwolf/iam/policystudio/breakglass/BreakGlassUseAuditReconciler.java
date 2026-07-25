package com.openwolf.iam.policystudio.breakglass;

import org.springframework.stereotype.Service;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.scheduling.annotation.Scheduled;

/**
 * Projects durable A6 Cerbos ALLOW decisions into C6 {@code break_glass.used} evidence. The immutable
 * active bundle id identifies the grant issuance; the Cerbos call id is the idempotency/correlation key.
 * Decisions lacking attributable principal metadata are ignored rather than fabricating an actor.
 */
@Service
@EnableScheduling
public class BreakGlassUseAuditReconciler {

    private final BreakGlassDecisionEventRepository decisions;
    private final BreakGlassIssuanceRepository issuances;
    private final BreakGlassAuditPartition audit;
    private final BreakGlassBundleGrantRepository bundleGrants;

    public BreakGlassUseAuditReconciler(BreakGlassDecisionEventRepository decisions,
                                        BreakGlassIssuanceRepository issuances,
                                        BreakGlassAuditPartition audit,
                                        BreakGlassBundleGrantRepository bundleGrants) {
        this.decisions = decisions;
        this.issuances = issuances;
        this.audit = audit;
        this.bundleGrants = bundleGrants;
    }

    public int reconcile() {
        int recorded = 0;
        for (BreakGlassDecisionEvent decision :
                decisions.findByDecisionAndProcessedFalseOrderByOccurredAt("ALLOW")) {
            boolean matched = false;
            java.util.List<String> grantIds = bundleGrants.findByBundleId(decision.getActivePolicyVersion())
                    .stream().map(BreakGlassBundleGrant::getGrantId).toList();
            java.util.List<BreakGlassIssuance> eligible = new java.util.ArrayList<>();
            for (BreakGlassIssuance issuance : issuances.findAllById(grantIds)) {
                if (!issuance.getTenantId().equals(decision.getTenantId())
                        || issuance.getState() != BreakGlassIssuance.State.ACTIVATED
                        || !issuance.getResourceKind().equals(decision.getResourceKind())
                        || !issuance.getAction().equals(decision.getAction())
                        || !decision.getPrincipalRoles().contains(issuance.getRole())
                        || decision.getOccurredAt().isBefore(issuance.getIssuedAt())
                        || !decision.getOccurredAt().isBefore(issuance.getExpiresAt())) {
                    continue;
                }
                eligible.add(issuance);
            }
            // Compiler precedence: a newer grant overlays the exact tuple during its window and gates the
            // older grant outside that window. Attribute one ALLOW to that newest eligible issuance only.
            BreakGlassIssuance decidingGrant = eligible.stream()
                    .max(java.util.Comparator.comparing(BreakGlassIssuance::getIssuedAt)).orElse(null);
            if (decidingGrant != null) {
                audit.recordUsed(decidingGrant.getGrantId(), decidingGrant.grant(), decision.getPrincipalId(),
                        decision.getAction(), decision.getCerbosCallId());
                matched = true;
                recorded++;
            }
            if (matched) {
                decision.markProcessed();
                decisions.save(decision);
            }
        }
        return recorded;
    }

    /** Continuously projects newly-ingested durable decision rows; audit uniqueness makes rescans safe. */
    @Scheduled(fixedDelayString = "${iam.break-glass.use-reconcile-ms:5000}")
    public void scheduledReconcile() {
        reconcile();
    }
}
