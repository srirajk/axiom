package com.openwolf.iam.auth;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AccessTokenAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.web.authentication.OAuth2AccessTokenResponseAuthenticationSuccessHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.LinkedHashSet;
import java.util.Set;

/**
 * The token response reports the scope actually issued (RFC 6749 section 5.1). When issuance narrowed the access
 * token's {@code scope} claim (a business scope the person is not entitled to), the response's {@code scope} follows the
 * token rather than the request. Everything else is the standard Spring Authorization Server response.
 */
public final class IssuedScopeTokenResponseHandler implements AuthenticationSuccessHandler {
    private static final ObjectMapper JSON = new ObjectMapper();
    private final OAuth2AccessTokenResponseAuthenticationSuccessHandler delegate =
            new OAuth2AccessTokenResponseAuthenticationSuccessHandler();

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                        Authentication authentication) throws IOException, ServletException {
        if (authentication instanceof OAuth2AccessTokenAuthenticationToken issued) {
            OAuth2AccessToken access = issued.getAccessToken();
            Set<String> claimed = claimedScopes(access.getTokenValue());
            if (claimed != null && !claimed.equals(access.getScopes())) {
                OAuth2AccessToken corrected = new OAuth2AccessToken(access.getTokenType(), access.getTokenValue(),
                        access.getIssuedAt(), access.getExpiresAt(), claimed);
                authentication = new OAuth2AccessTokenAuthenticationToken(issued.getRegisteredClient(),
                        (Authentication) issued.getPrincipal(), corrected, issued.getRefreshToken(),
                        issued.getAdditionalParameters());
            }
        }
        delegate.onAuthenticationSuccess(request, response, authentication);
    }

    /** The {@code scope} claim of a JWT this server just minted; null for anything that is not such a JWT. */
    static Set<String> claimedScopes(String token) {
        String[] parts = token.split("\\.");
        if (parts.length != 3) return null;
        try {
            JsonNode claims = JSON.readTree(new String(Base64.getUrlDecoder().decode(parts[1]), StandardCharsets.UTF_8));
            JsonNode scope = claims.get("scope");
            if (scope == null) return null;
            Set<String> values = new LinkedHashSet<>();
            if (scope.isTextual()) {
                for (String value : scope.asText().trim().split("\\s+")) if (!value.isBlank()) values.add(value);
            } else if (scope.isArray()) {
                scope.forEach(value -> values.add(value.asText()));
            } else {
                return null;
            }
            return values;
        } catch (IOException | IllegalArgumentException notAJwt) {
            return null;
        }
    }
}
