package com.openwolf.iam.tenancy;

import com.openwolf.iam.policystudio.lifecycle.GitCommitResolver;
import com.openwolf.iam.policystudio.lifecycle.PolicyBundle;
import com.openwolf.iam.policystudio.lifecycle.PolicyBundleRecord;
import com.openwolf.iam.policystudio.lifecycle.PolicyBundleRepository;
import com.openwolf.iam.policystudio.lifecycle.PromotedBundleLoadException;
import com.openwolf.iam.policystudio.lifecycle.PromotedBundleLoader;
import org.springframework.stereotype.Component;

/** Production B4→C5 bootstrap publication seam. */
@Component
public class RuntimeBootstrapPolicyPublisher implements BootstrapPolicyPublisher {

    private final PromotedBundleLoader loader;
    private final PolicyBundleRepository bundles;
    private final GitCommitResolver git;

    public RuntimeBootstrapPolicyPublisher(
            PromotedBundleLoader loader, PolicyBundleRepository bundles, GitCommitResolver git) {
        this.loader = loader;
        this.bundles = bundles;
        this.git = git;
    }

    @Override
    public void publishAndPersist(PolicyBundle bundle) {
        if (!loader.isConfigured()) {
            throw new PromotedBundleLoadException(bundle.bundleId(), "<unconfigured>",
                    new IllegalStateException("no runtime policy backend configured for tenant bootstrap"));
        }
        loader.load(bundle);
        loader.awaitPublication(bundle);

        PolicyBundleRecord existing = bundles.findById(bundle.bundleId()).orElse(null);
        if (existing != null) {
            if (!existing.getTenantId().equals(bundle.tenantId())
                    || !existing.getCanonicalContent().equals(bundle.canonicalContent())) {
                throw new ProvisioningException("bootstrap bundle id '" + bundle.bundleId()
                        + "' already exists with different immutable content");
            }
            return; // idempotent retry: exact immutable record already exists
        }
        bundles.save(new PolicyBundleRecord(bundle, git.currentCommit()));
    }
}
