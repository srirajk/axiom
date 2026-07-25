package com.openwolf.iam.policystudio;

/** The sole resource kind exposed by the AXM-1 Axiom platform-policy contract. */
public final class PlatformResourceKind {
    public static final String IAM_RESOURCE = "iam-resource";

    private PlatformResourceKind() {}

    public static String require(String resourceKind) {
        if (!IAM_RESOURCE.equals(resourceKind)) {
            throw new IllegalArgumentException("resource kind must be the AXM platform contract kind '"
                    + IAM_RESOURCE + "'");
        }
        return resourceKind;
    }
}
