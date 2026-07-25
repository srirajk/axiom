package com.openwolf.iam.policystudio;

import java.util.List;
import java.util.Objects;

/**
 * A Cerbos scope, parsed as an ordered list of dot-delimited <em>segments</em> (Axiom Story C2.4).
 *
 * <p>Cerbos scopes are hierarchical and dot-delimited (e.g. {@code "acme.uk.london"}); the parent
 * of {@code acme.uk} is {@code acme}, whose parent is the root {@code ""}. Containment MUST be
 * decided <b>segment-by-segment</b>, never by raw string prefix:
 *
 * <pre>
 *   author "tenant.a"  contains "tenant.a"          → true  (exact tenant)
 *   author "tenant.a"  contains "tenant.a.london"   → true  ONLY if descendants are enabled
 *   author "tenant.a"  contains "tenant.ab"         → FALSE (segment "a" != "ab")
 *   author "tenant.a"  contains "tenant.a.b" (str)  handled as segments, not "startsWith")
 * </pre>
 *
 * The {@code tenant.a} / {@code tenant.ab} case is the whole point: a naive
 * {@code candidate.startsWith(author)} would accept {@code tenant.ab}, silently widening the
 * author's blast radius into a sibling tenant. Comparing parsed segment lists closes that hole.
 */
public final class TenantScope {

    private static final char DELIMITER = '.';

    private final List<String> segments;

    private TenantScope(List<String> segments) {
        this.segments = List.copyOf(segments);
    }

    /**
     * Parse a raw Cerbos scope string into segments.
     *
     * @throws IllegalArgumentException if the scope is null, or contains an empty segment
     *         (leading/trailing/double dot) — a malformed scope is never silently normalised.
     */
    public static TenantScope of(String raw) {
        if (raw == null) {
            throw new IllegalArgumentException("scope must not be null");
        }
        String trimmed = raw.strip();
        if (trimmed.isEmpty()) {
            return new TenantScope(List.of()); // root scope
        }
        String[] parts = trimmed.split("\\" + DELIMITER, -1); // -1: keep trailing empties so we can reject them
        for (String p : parts) {
            if (p.isEmpty()) {
                throw new IllegalArgumentException(
                        "scope '" + raw + "' has an empty segment (leading/trailing/double dot)");
            }
            if (p.strip().length() != p.length()) {
                throw new IllegalArgumentException(
                        "scope '" + raw + "' has a segment with surrounding whitespace");
            }
        }
        return new TenantScope(List.of(parts));
    }

    public List<String> segments() {
        return segments;
    }

    public boolean isRoot() {
        return segments.isEmpty();
    }

    /** Canonical scope string ({@code ""} for root). */
    public String value() {
        return String.join(String.valueOf(DELIMITER), segments);
    }

    /** True iff {@code other} is the exact same tenant (segment-equal). */
    public boolean isSameScope(TenantScope other) {
        return segments.equals(other.segments);
    }

    /**
     * True iff {@code other} is a <b>strict descendant</b>: it has strictly more segments than
     * this scope AND this scope's segments are an exact segment-prefix of {@code other}'s.
     */
    public boolean isStrictDescendant(TenantScope other) {
        if (other.segments.size() <= segments.size()) {
            return false;
        }
        return other.segments.subList(0, segments.size()).equals(segments);
    }

    /**
     * Structural containment used by the generation gate: is {@code candidate} inside this
     * author scope's subtree?
     *
     * @param allowDescendants when {@code false} (the default posture, "subscopes disabled") only
     *                         the exact same tenant is inside the subtree; a descendant is rejected.
     *                         When {@code true} a strict descendant is also inside the subtree.
     */
    public boolean contains(TenantScope candidate, boolean allowDescendants) {
        if (isSameScope(candidate)) {
            return true;
        }
        return allowDescendants && isStrictDescendant(candidate);
    }

    @Override
    public boolean equals(Object o) {
        return o instanceof TenantScope ts && ts.segments.equals(segments);
    }

    @Override
    public int hashCode() {
        return Objects.hash(segments);
    }

    @Override
    public String toString() {
        return "TenantScope[" + (isRoot() ? "(root)" : value()) + "]";
    }
}
