package com.openwolf.iam.auth;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.web.authentication.WebAuthenticationDetails;

import java.time.Instant;

/**
 * Records when an interactive browser login completed (Phase 3.9). Attached by the form-login filter, carried with the
 * authenticated principal into the OAuth authorization, and emitted as {@code auth_time}/{@code acr} on tokens minted
 * for that login. Serializable with the authorization record.
 */
public final class AssuranceAuthenticationDetails extends WebAuthenticationDetails {
    private static final long serialVersionUID = 1L;
    private final Instant authenticatedAt;
    private final String acr;

    public AssuranceAuthenticationDetails(HttpServletRequest request, Instant authenticatedAt, String acr) {
        super(request);
        this.authenticatedAt = authenticatedAt;
        this.acr = acr;
    }

    public Instant authenticatedAt() { return authenticatedAt; }

    public String acr() { return acr; }
}
