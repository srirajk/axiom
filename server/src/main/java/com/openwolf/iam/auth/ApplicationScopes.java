package com.openwolf.iam.auth;

/** Stable Axiom scopes that an ordinary registered application client may request. */
public final class ApplicationScopes {
    public static final String APPLICATION_READ = "axiom.application.read";
    public static final String SUBJECT_CONTEXT_READ = "axiom.subject-context.read";
    /** Service-only permission to request application-access decisions. */
    public static final String PLATFORM_AUTHZ_DECIDE = "axiom.platform-authz.decide";

    private ApplicationScopes() {}
}
