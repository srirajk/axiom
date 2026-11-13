package com.openwolf.iam.auth;

import java.net.URI;
import java.util.List;

/** HTTPS resource identifiers owned by a tenant application. A trailing slash denotes a path prefix. */
public final class ApplicationResourceUris {
    private ApplicationResourceUris() {}

    public static List<String> validate(List<String> values) {
        if (values == null) return List.of();
        if (values.size() > 32) throw new IllegalArgumentException("Too many application resource URIs");
        List<String> checked = values.stream().map(value -> {
            URI uri = parse(value);
            if (uri.getRawQuery() != null && uri.getRawPath().endsWith("/")) {
                throw new IllegalArgumentException("A resource path prefix cannot contain a query");
            }
            return value;
        }).toList();
        if (checked.stream().distinct().count() != checked.size()) {
            throw new IllegalArgumentException("Duplicate application resource URI");
        }
        return checked;
    }

    public static boolean matches(String resource, List<String> registrations) {
        URI requested;
        try { requested = parse(resource); }
        catch (IllegalArgumentException invalid) { return false; }
        if (registrations == null) return false;
        for (String registration : registrations) {
            URI allowed = parse(registration);
            if (!requested.getHost().equalsIgnoreCase(allowed.getHost()) || requested.getPort() != allowed.getPort()) continue;
            if (allowed.getRawPath().endsWith("/") && allowed.getRawQuery() == null) {
                if (requested.getRawPath().startsWith(allowed.getRawPath())) return true;
            } else if (requested.equals(allowed)) return true;
        }
        return false;
    }

    public static boolean overlaps(String first, String second) {
        URI a = parse(first), b = parse(second);
        if (!a.getHost().equalsIgnoreCase(b.getHost()) || a.getPort() != b.getPort()) return false;
        if (a.getRawPath().endsWith("/") && a.getRawQuery() == null && b.getRawPath().startsWith(a.getRawPath())) return true;
        if (b.getRawPath().endsWith("/") && b.getRawQuery() == null && a.getRawPath().startsWith(b.getRawPath())) return true;
        return a.equals(b);
    }

    private static URI parse(String value) {
        try {
            if (value == null || value.isBlank() || value.length() > 2048) throw new IllegalArgumentException();
            URI uri = URI.create(value);
            String path = uri.getRawPath();
            if (!"https".equalsIgnoreCase(uri.getScheme()) || uri.getHost() == null || uri.getHost().isBlank()
                    || uri.getRawUserInfo() != null || uri.getRawFragment() != null || uri.getPort() == 0
                    || uri.getPort() > 65535 || uri.getRawAuthority() == null || path == null || path.isEmpty()
                    || path.contains("/../") || path.contains("/./") || path.endsWith("/..") || path.endsWith("/.")
                    || path.toLowerCase(java.util.Locale.ROOT).matches(".*%(?:2e|2f|5c).*")) {
                throw new IllegalArgumentException();
            }
            return uri;
        } catch (IllegalArgumentException invalid) {
            throw new IllegalArgumentException("Invalid HTTPS application resource URI");
        }
    }
}
