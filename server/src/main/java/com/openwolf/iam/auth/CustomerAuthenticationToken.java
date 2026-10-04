package com.openwolf.iam.auth;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.List;

/**
 * A customer (CIAM) signed in through Axiom's customer login page for one tenant. Deliberately a different type from a
 * workforce login: the authorization server and token customizer refuse to mix the two populations. The name is the
 * customer's stable id; {@code tokenVersion} pins the credential/suspension generation at sign-in time, so a later
 * suspension or credential recovery stops issuance and refresh from this login.
 */
public final class CustomerAuthenticationToken extends AbstractAuthenticationToken {
    private static final long serialVersionUID = 1L;
    public static final String AUTHORITY = "POPULATION_CUSTOMER";

    private final String customerId;
    private final String tenantId;
    private final long tokenVersion;

    public CustomerAuthenticationToken(String customerId, String tenantId, long tokenVersion, Object details) {
        super(List.of(new SimpleGrantedAuthority(AUTHORITY)));
        this.customerId = customerId;
        this.tenantId = tenantId;
        this.tokenVersion = tokenVersion;
        setDetails(details);
        setAuthenticated(true);
    }

    @Override public Object getCredentials() { return null; }
    @Override public Object getPrincipal() { return customerId; }
    @Override public String getName() { return customerId; }
    public String tenantId() { return tenantId; }
    public long tokenVersion() { return tokenVersion; }
}
