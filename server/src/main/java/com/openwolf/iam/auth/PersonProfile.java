package com.openwolf.iam.auth;

import java.util.LinkedHashMap;
import java.util.Map;

/** OIDC person-name projection from Axiom and SCIM-owned principal attributes. */
public final class PersonProfile {
    private PersonProfile() {}

    public static Map<String, Object> claims(Map<String, Object> attributes) {
        Map<String, Object> result = new LinkedHashMap<>();
        String given = value(attributes.get("given_name"));
        String family = value(attributes.get("family_name"));
        Object scim = attributes.get("name");
        if (scim instanceof Map<?, ?> name) {
            if (given == null) given = value(name.get("givenName"));
            if (family == null) family = value(name.get("familyName"));
        }
        String display = value(attributes.get("display_name"));
        if (display == null) display = value(attributes.get("displayName"));
        if (display == null && scim instanceof Map<?, ?> name) display = value(name.get("formatted"));
        if (display == null) display = join(given, family);
        if (display != null) result.put("name", display);
        if (given != null) result.put("given_name", given);
        if (family != null) result.put("family_name", family);
        return result;
    }

    private static String join(String given, String family) {
        if (given == null) return family;
        return family == null ? given : given + " " + family;
    }

    private static String value(Object raw) {
        if (!(raw instanceof String text)) return null;
        String trimmed = text.trim();
        return trimmed.isEmpty() ? null : trimmed;
    }
}
