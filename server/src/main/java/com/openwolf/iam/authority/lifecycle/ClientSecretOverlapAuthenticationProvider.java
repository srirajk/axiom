package com.openwolf.iam.authority.lifecycle;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;

/**
 * Accepts a confidential client's previous secret only inside its declared rotation overlap. The current secret is
 * always left to the standard provider (this returns null), and anything else falls through to it and fails there.
 * Inactive application clients are not resolvable through the repository it is given.
 */
public final class ClientSecretOverlapAuthenticationProvider implements AuthenticationProvider {
    private final RegisteredClientRepository clients;
    private final PasswordEncoder passwords;
    private final ClientSecretOverlapStore overlaps;

    public ClientSecretOverlapAuthenticationProvider(RegisteredClientRepository clients, PasswordEncoder passwords,
                                                     ClientSecretOverlapStore overlaps) {
        this.clients = clients;
        this.passwords = passwords;
        this.overlaps = overlaps;
    }

    @Override
    public Authentication authenticate(Authentication authentication) {
        OAuth2ClientAuthenticationToken request = (OAuth2ClientAuthenticationToken) authentication;
        ClientAuthenticationMethod method = request.getClientAuthenticationMethod();
        if (!ClientAuthenticationMethod.CLIENT_SECRET_BASIC.equals(method)
                && !ClientAuthenticationMethod.CLIENT_SECRET_POST.equals(method)) return null;
        if (!(request.getCredentials() instanceof String presented) || request.getPrincipal() == null) return null;
        String clientId = request.getPrincipal().toString();
        var previous = overlaps.previousHash(clientId);
        if (previous.isEmpty()) return null;
        RegisteredClient client = clients.findByClientId(clientId);
        if (client == null || !client.getClientAuthenticationMethods().contains(method)) return null;
        if (client.getClientSecret() != null && passwords.matches(presented, client.getClientSecret())) return null;
        if (!passwords.matches(presented, previous.get())) return null;
        return new OAuth2ClientAuthenticationToken(client, method, presented);
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return OAuth2ClientAuthenticationToken.class.isAssignableFrom(authentication);
    }
}
