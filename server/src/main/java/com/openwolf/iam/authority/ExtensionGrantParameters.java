package com.openwolf.iam.authority;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.util.StringUtils;

import java.util.LinkedHashSet;
import java.util.Set;
import java.util.UUID;

/** Strict single-valued parameter parsing for Phase 3 extension grants. Secret values are never echoed. */
public final class ExtensionGrantParameters {
    private ExtensionGrantParameters() {}

    public static String required(HttpServletRequest request, String name) {
        String value = optional(request, name);
        if (!StringUtils.hasText(value)) invalid();
        return value;
    }

    public static String optional(HttpServletRequest request, String name) {
        String[] values = request.getParameterMap().get(name);
        if (values == null) return null;
        if (values.length != 1 || !StringUtils.hasText(values[0]) || values[0].length() > 8192) invalid();
        return values[0].trim();
    }

    public static UUID uuid(HttpServletRequest request, String name, boolean required) {
        String value = required ? required(request, name) : optional(request, name);
        if (value == null) return null;
        try {
            return UUID.fromString(value);
        } catch (IllegalArgumentException malformed) {
            invalid();
            return null;
        }
    }

    public static Set<String> scopes(HttpServletRequest request) {
        Set<String> scopes = new LinkedHashSet<>();
        for (String scope : required(request, "scope").split("\\s+")) {
            if (!scope.matches("[A-Za-z0-9][A-Za-z0-9._:-]{0,127}")) invalid();
            scopes.add(scope);
        }
        return scopes;
    }

    /** Parameters that would let another credential (an access, refresh or actor token) stand in for authority. */
    public static void forbid(HttpServletRequest request, String... names) {
        for (String name : names) if (request.getParameterMap().containsKey(name)) invalid();
    }

    public static void invalid() {
        throw new OAuth2AuthenticationException(new OAuth2Error(OAuth2ErrorCodes.INVALID_REQUEST));
    }
}
