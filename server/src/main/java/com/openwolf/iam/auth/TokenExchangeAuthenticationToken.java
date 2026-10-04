package com.openwolf.iam.auth;

import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationGrantAuthenticationToken;
import org.springframework.security.oauth2.jwt.Jwt;

import java.util.Map;
import java.util.Set;

/** Authenticated-client request for Axiom's RFC 8693 on-behalf-of profile. */
public final class TokenExchangeAuthenticationToken extends OAuth2AuthorizationGrantAuthenticationToken {
    private final String subjectToken;
    private final String audience;
    private final Set<String> requestedScopes;
    private AuthorityContext authorityContext;
    private com.openwolf.iam.invocation.InvocationContextService.Request invocation =
            com.openwolf.iam.invocation.InvocationContextService.Request.NONE;

    /** Server-resolved authority used only during this token-generation request. */
    public record AuthorityContext(Jwt subject, String audience, String purpose,
                                   String authorityProfile, String authorityId, String delegationId,
                                   String tokenUse, String identityKind, String workloadId,
                                   String workloadRef, String actorClientId, InvocationBinding invocation) {
        public AuthorityContext(Jwt subject, String audience, String purpose, String authorityProfile, String authorityId,
                                String delegationId, String tokenUse, String identityKind, String workloadId,
                                String workloadRef, String actorClientId) {
            this(subject, audience, purpose, authorityProfile, authorityId, delegationId, tokenUse, identityKind,
                    workloadId, workloadRef, actorClientId, null);
        }
    }

    /** Opaque invocation-context reference carried by a context-bound token (Phase 2.4). */
    public record InvocationBinding(String contextId, long version, int depth) {}

    public TokenExchangeAuthenticationToken(Authentication clientPrincipal, String subjectToken,
                                             String audience, Set<String> requestedScopes,
                                             Map<String, Object> additionalParameters) {
        super(TokenExchangeConstants.GRANT_TYPE, clientPrincipal, additionalParameters);
        this.subjectToken = subjectToken;
        this.audience = audience;
        this.requestedScopes = Set.copyOf(requestedScopes);
    }

    public String subjectToken() { return subjectToken; }
    public String audience() { return audience; }
    public Set<String> requestedScopes() { return requestedScopes; }

    public void bindAuthority(AuthorityContext authorityContext) {
        if (this.authorityContext != null) {
            throw new IllegalStateException("token exchange authority is already bound");
        }
        this.authorityContext = java.util.Objects.requireNonNull(authorityContext);
    }

    public AuthorityContext authorityContext() { return authorityContext; }

    public com.openwolf.iam.invocation.InvocationContextService.Request invocation() { return invocation; }

    private String delegationPurpose;

    /** Phase 3.2 purpose selector for customer delegation; null when absent. */
    public String delegationPurpose() { return delegationPurpose; }

    void delegationPurpose(String delegationPurpose) { this.delegationPurpose = delegationPurpose; }

    void invocation(com.openwolf.iam.invocation.InvocationContextService.Request invocation) {
        this.invocation = java.util.Objects.requireNonNull(invocation);
    }
}
