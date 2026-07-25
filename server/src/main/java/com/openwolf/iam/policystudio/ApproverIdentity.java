package com.openwolf.iam.policystudio;

import java.util.Set;

/**
 * The VERIFIED identity of the principal approving a consequence review (Axiom H3). Built from the
 * authenticated JWT at the controller — the tenant claim, the {@code sub}, and the granted roles — never
 * from a request body. {@link ConsequenceApprovalService#approve} enforces the approver gate over this:
 * an approver role is required, {@code platform_admin} alone is not an auto-approver, the approver must be
 * in the review's tenant, and a {@code null} subject fails closed.
 *
 * @param tenantId the approver's tenant (must equal the review's tenant)
 * @param subject  the approver's verified {@code sub} ({@code null} ⇒ fail closed)
 * @param roles    the approver's granted roles at decision time
 */
public record ApproverIdentity(String tenantId, String subject, Set<String> roles) {

    public ApproverIdentity {
        roles = roles == null ? Set.of() : Set.copyOf(roles);
    }
}
