package com.openwolf.iam.auth;

import com.openwolf.iam.service.IamSessionService;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenIntrospection;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2TokenIntrospectionAuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2TokenIntrospectionAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;

import java.time.Instant;
import java.util.UUID;

/** Applies the durable session boundary to RFC 7662 introspection results. */
public final class SessionAwareIntrospectionAuthenticationProvider implements AuthenticationProvider {
    private final AuthenticationProvider delegate;
    private final OAuth2AuthorizationService authorizations;
    private final IamSessionService sessions;
    private final JwtDecoder localDecoder;

    public SessionAwareIntrospectionAuthenticationProvider(RegisteredClientRepository clients,
                                                           OAuth2AuthorizationService authorizations,
                                                           IamSessionService sessions, JwtDecoder localDecoder) {
        this(new OAuth2TokenIntrospectionAuthenticationProvider(clients, authorizations), authorizations, sessions, localDecoder);
    }

    SessionAwareIntrospectionAuthenticationProvider(AuthenticationProvider delegate,
                                                   OAuth2AuthorizationService authorizations,
                                                   IamSessionService sessions, JwtDecoder localDecoder) {
        this.delegate = delegate;
        this.authorizations = authorizations;
        this.sessions = sessions;
        this.localDecoder = localDecoder;
    }

    @Override
    public Authentication authenticate(Authentication authentication) {
        Authentication result = delegate.authenticate(authentication);
        if (!(result instanceof OAuth2TokenIntrospectionAuthenticationToken introspection)) return result;
        if (authorizations.findByToken(introspection.getToken(), OAuth2TokenType.ACCESS_TOKEN) == null) {
            return locallyIssued(introspection);
        }
        OAuth2TokenIntrospection claims = introspection.getTokenClaims();
        if (claims == null) return result;
        Object rawSession = claims.getClaims().get("sid");
        Object rawTenant = claims.getClaims().get("tenant_id");
        boolean active = false;
        if (rawSession instanceof String sid && rawTenant instanceof String tenant) {
            try {
                active = sessions.active(UUID.fromString(sid), tenant, Instant.now());
            } catch (IllegalArgumentException ignored) {
                active = false;
            }
        }
        if (!active) {
            return inactive(introspection);
        }
        OAuth2TokenIntrospection.Builder rebuilt = OAuth2TokenIntrospection.builder(true);
        claims.getClaims().forEach(rebuilt::claim);
        rebuilt.active(true);
        return new OAuth2TokenIntrospectionAuthenticationToken(introspection.getToken(),
                (org.springframework.security.core.Authentication) introspection.getPrincipal(), rebuilt.build());
    }

    private Authentication locallyIssued(OAuth2TokenIntrospectionAuthenticationToken introspection) {
        try {
            Jwt jwt = localDecoder.decode(introspection.getToken());
            String sid = jwt.getClaimAsString("sid");
            String tenant = jwt.getClaimAsString("tenant_id");
            if (sid == null || tenant == null || tenant.isBlank()
                    || jwt.getExpiresAt() == null || !jwt.getExpiresAt().isAfter(Instant.now())
                    || !sessions.active(UUID.fromString(sid), tenant, Instant.now())) {
                return inactive(introspection);
            }
            OAuth2TokenIntrospection.Builder rebuilt = OAuth2TokenIntrospection.builder(true);
            jwt.getClaims().forEach(rebuilt::claim);
            rebuilt.tokenType("Bearer").active(true);
            return new OAuth2TokenIntrospectionAuthenticationToken(introspection.getToken(),
                    (org.springframework.security.core.Authentication) introspection.getPrincipal(), rebuilt.build());
        } catch (JwtException | IllegalArgumentException ex) {
            return inactive(introspection);
        }
    }

    private Authentication inactive(OAuth2TokenIntrospectionAuthenticationToken introspection) {
        return new OAuth2TokenIntrospectionAuthenticationToken(introspection.getToken(),
                (org.springframework.security.core.Authentication) introspection.getPrincipal(), introspection.getTokenTypeHint(),
                java.util.Map.of("active", false));
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return OAuth2TokenIntrospectionAuthenticationToken.class.isAssignableFrom(authentication);
    }
}
