package com.openwolf.iam.tenancy;

import com.openwolf.iam.policystudio.lifecycle.PolicyBundle;

import java.nio.file.Path;
import java.util.Map;

/**
 * A staged, content-addressed tenant policy bootstrap bundle (Axiom B4). Built from the current
 * approved base ceiling + the B1 deny-all template: one deny-all child resource policy per base
 * resource kind, each explicitly {@code EFFECT_DENY}-ing every base-ceiling tuple so nothing falls
 * through the parental-consent posture. The {@code policyVersion} is a content hash of the bundle,
 * so the same tenant + same ceiling always yields the same version (a retry never forks a new one).
 *
 * @param tenantId       the tenant this bundle bootstraps
 * @param policyVersion  content-addressed version id (stable across retries)
 * @param stagingDir     where the child policies were written, ALONGSIDE (never overwriting) the
 *                       live bundle — retained for the evidence-retention period on deprovision
 * @param childByResource canonical child YAML keyed by the platform resource kind
 * @param policyBundle    the normal C5 tenant-wide immutable bundle published and persisted before
 *                        directory activation; {@code policyVersion == policyBundle.bundleId()}
 */
public record TenantBootstrapBundle(
        String tenantId,
        String policyVersion,
        Path stagingDir,
        Map<String, String> childByResource,
        PolicyBundle policyBundle) {

    public TenantBootstrapBundle {
        childByResource = Map.copyOf(childByResource);
        if (policyBundle == null) {
            throw new IllegalArgumentException("policyBundle must be set");
        }
        if (!tenantId.equals(policyBundle.tenantId())) {
            throw new IllegalArgumentException("bootstrap tenant does not match policy bundle tenant");
        }
        if (!policyVersion.equals(policyBundle.bundleId())) {
            throw new IllegalArgumentException("bootstrap policyVersion must equal policyBundle.bundleId");
        }
    }
}
