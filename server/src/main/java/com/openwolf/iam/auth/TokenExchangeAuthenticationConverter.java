package com.openwolf.iam.auth;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.util.StringUtils;

import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;

/** Strict RFC 8693 request parser. Secret-bearing parameters are never copied to diagnostics. */
public final class TokenExchangeAuthenticationConverter implements AuthenticationConverter {

    @Override
    public Authentication convert(HttpServletRequest request) {
        if (!TokenExchangeConstants.GRANT_TYPE_VALUE.equals(request.getParameter("grant_type"))) return null;

        Authentication clientPrincipal = SecurityContextHolder.getContext().getAuthentication();
        String subjectToken = requiredSingle(request, TokenExchangeConstants.SUBJECT_TOKEN);
        String subjectTokenType = requiredSingle(request, TokenExchangeConstants.SUBJECT_TOKEN_TYPE);
        if (!TokenExchangeConstants.ACCESS_TOKEN_TYPE.equals(subjectTokenType)) invalidRequest();
        if (request.getParameterMap().containsKey(TokenExchangeConstants.ACTOR_TOKEN)) invalidRequest();

        String requestedTokenType = optionalSingle(request, TokenExchangeConstants.REQUESTED_TOKEN_TYPE);
        if (requestedTokenType != null && !TokenExchangeConstants.ACCESS_TOKEN_TYPE.equals(requestedTokenType)) {
            invalidRequest();
        }

        String audience = optionalSingle(request, TokenExchangeConstants.AUDIENCE);
        String resource = optionalSingle(request, TokenExchangeConstants.RESOURCE);
        if ((audience == null) == (resource == null)) invalidRequest();
        String target = audience != null ? audience : resource;
        if (target.length() > 512) invalidRequest();

        if (request.getParameterMap().containsKey(TokenExchangeConstants.PURPOSE)
                || request.getParameterMap().containsKey(TokenExchangeConstants.DELEGATION_ID)) invalidRequest();

        String scopeValue = requiredSingle(request, "scope");
        Set<String> scopes = parseScopes(scopeValue);
        if (scopes.isEmpty()) invalidRequest();

        Map<String, Object> additional = new LinkedHashMap<>();
        additional.put(TokenExchangeConstants.SUBJECT_TOKEN_TYPE, subjectTokenType);
        additional.put(TokenExchangeConstants.REQUESTED_TOKEN_TYPE, TokenExchangeConstants.ACCESS_TOKEN_TYPE);
        additional.put(audience != null ? TokenExchangeConstants.AUDIENCE : TokenExchangeConstants.RESOURCE, target);
        additional.put("scope", String.join(" ", scopes));
        return new TokenExchangeAuthenticationToken(clientPrincipal, subjectToken, target, scopes, additional);
    }

    private static Set<String> parseScopes(String value) {
        Set<String> scopes = new LinkedHashSet<>();
        for (String scope : value.trim().split("\\s+")) {
            if (!scope.matches("[A-Za-z0-9][A-Za-z0-9._:-]{0,127}")) invalidRequest();
            scopes.add(scope);
        }
        return scopes;
    }

    private static String requiredSingle(HttpServletRequest request, String name) {
        String value = optionalSingle(request, name);
        if (!StringUtils.hasText(value)) invalidRequest();
        return value;
    }

    private static String optionalSingle(HttpServletRequest request, String name) {
        String[] values = request.getParameterMap().get(name);
        if (values == null) return null;
        if (values.length != 1 || !StringUtils.hasText(values[0])) invalidRequest();
        return values[0].trim();
    }

    private static void invalidRequest() {
        throw new OAuth2AuthenticationException(new OAuth2Error(OAuth2ErrorCodes.INVALID_REQUEST));
    }
}
