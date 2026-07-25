package com.openwolf.iam.policystudio.lifecycle;

/**
 * Thrown when a promoted candidate bundle cannot be materialised into the Cerbos-watched runtime-policies
 * directory (S1a). It fail-closes the promotion: the surrounding {@code @Transactional} promote rolls back
 * the activation CAS, so a tenant is never advanced to a bundle the serving PDP could not be given.
 */
public class PromotedBundleLoadException extends RuntimeException {

    public PromotedBundleLoadException(String bundleId, String dir, Throwable cause) {
        super("failed to load promoted bundle '" + bundleId + "' into runtime-policies dir '" + dir
                + "' — refusing to activate a bundle the serving PDP cannot be given", cause);
    }
}
