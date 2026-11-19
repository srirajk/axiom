package com.openwolf.iam.auth;

import java.util.List;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationGrantAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;

/**
 * RFC 8707 audience of a person's access token. A resource strictly below a registered prefix of the client's
 * application is a protected resource of its own (an MCP server, such as one Argus block), so the token names it as
 * its first audience. The application's audience stays the second member: it is what every existing resource server
 * of the application (the Gateway's native JWT check, Axiom's exchange) already validates, so old and new resource
 * servers both admit the token while the resource server for that one resource can refuse every other token.
 * Any other request keeps the single application audience, exactly as before.
 */
public final class ResourceAudience {
    public static final String PARAMETER = "resource";
    private static final OAuth2Error INVALID_TARGET = new OAuth2Error("invalid_target");

    private ResourceAudience() {}

    /** The audience to issue for this bound resource (null: none was asked for). */
    public static List<String> of(String resource, String audience, List<String> resourceUris) {
        if (resource == null || resource.equals(audience) || !ApplicationResourceUris.below(resource, resourceUris)) {
            return List.of(audience);
        }
        return List.of(resource, audience);
    }

    /**
     * The resource the grant is bound to: the authorization request's, else the token request's. When both are present
     * they must be the same resource (RFC 8707 2.2: a token request cannot widen the grant), else invalid_target. A
     * refresh keeps the resource bound at authorization.
     */
    public static String requested(JwtEncodingContext context) {
        String authorized = null;
        OAuth2Authorization authorization = context.getAuthorization();
        if (authorization != null) {
            OAuth2AuthorizationRequest request = authorization.getAttribute(OAuth2AuthorizationRequest.class.getName());
            if (request != null) authorized = single(request.getAdditionalParameters().get(PARAMETER));
        }
        String asked = context.getAuthorizationGrant() instanceof OAuth2AuthorizationGrantAuthenticationToken grant
                ? single(grant.getAdditionalParameters().get(PARAMETER)) : null;
        if (authorized != null && asked != null && !authorized.equals(asked)) {
            throw new OAuth2AuthenticationException(INVALID_TARGET);
        }
        return authorized != null ? authorized : asked;
    }

    /** The application audience a token was issued for: its only member, or the second of [resource, audience]. */
    public static String applicationAudience(List<String> audiences) {
        if (audiences == null) return "";
        if (audiences.size() == 1) return audiences.getFirst();
        if (audiences.size() == 2) return audiences.get(1);
        return "";
    }

    /** True when the token was issued for this application: [audience], or [a resource below its prefix, audience]. */
    public static boolean issuedFor(Jwt token, String audience, List<String> resourceUris) {
        List<String> audiences = token.getAudience();
        if (audiences == null || audience == null) return false;
        if (audiences.size() == 1) return audience.equals(audiences.getFirst());
        return audiences.size() == 2 && audience.equals(audiences.get(1))
                && ApplicationResourceUris.below(audiences.getFirst(), resourceUris);
    }

    private static String single(Object value) {
        if (value == null) return null;
        if (value instanceof String text) return text;
        if (value instanceof String[] values && values.length == 1) return values[0];
        throw new OAuth2AuthenticationException(INVALID_TARGET);
    }
}
