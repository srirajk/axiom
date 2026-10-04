package com.openwolf.iam.auth;

import org.springframework.security.oauth2.jwt.Jwt;

import java.time.Duration;
import java.time.Instant;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

/**
 * Phase 3.9 verified authentication assurance carried in Axiom tokens: {@code auth_time} (when the human last
 * authenticated interactively), {@code acr} and {@code amr}. Axiom's only first-party authenticator is a password, so
 * the only assurance Axiom asserts is {@link #PASSWORD}; any stronger requirement fails closed until an authenticator
 * and an assurance vocabulary are selected (decision D-5). Tokens that do not record an interactive authentication
 * (impersonation, recovery, client credentials, tests that bypass login) carry no {@code auth_time} and therefore
 * never satisfy a freshness requirement.
 */
public final class AuthenticationAssurance {
    public static final String PASSWORD = "urn:openwolf:axiom:acr:pwd";
    public static final String CLAIM_AUTH_TIME = "auth_time";
    public static final String CLAIM_ACR = "acr";
    public static final String CLAIM_AMR = "amr";

    private AuthenticationAssurance() {}

    /** Claims for an interactive password authentication completed at {@code authenticatedAt}. */
    public static Map<String, Object> passwordClaims(Instant authenticatedAt) {
        return Map.of(CLAIM_AUTH_TIME, authenticatedAt.getEpochSecond(), CLAIM_ACR, PASSWORD, CLAIM_AMR, List.of("pwd"));
    }

    public static Optional<Instant> authTime(Jwt token) {
        Object raw = token.getClaims().get(CLAIM_AUTH_TIME);
        if (raw instanceof Number seconds) return Optional.of(Instant.ofEpochSecond(seconds.longValue()));
        if (raw instanceof Instant instant) return Optional.of(instant);
        return Optional.empty();
    }

    /**
     * True when the token records an interactive authentication with one of {@code acceptedAcr} no older than
     * {@code maxAge} (and not in the future beyond a small skew).
     */
    public static boolean satisfies(Jwt token, Collection<String> acceptedAcr, Duration maxAge, Instant now) {
        Optional<Instant> authTime = authTime(token);
        String acr = token.getClaimAsString(CLAIM_ACR);
        if (authTime.isEmpty() || acr == null || acceptedAcr == null || !Set.copyOf(acceptedAcr).contains(acr)) return false;
        Instant at = authTime.get();
        return !at.isAfter(now.plusSeconds(30)) && !at.isBefore(now.minus(maxAge));
    }

    /** Copies verified assurance from a subject token into an exchanged token (preserved, never upgraded). */
    public static void propagate(Jwt subject, java.util.function.BiConsumer<String, Object> claim) {
        Object authTime = subject.getClaims().get(CLAIM_AUTH_TIME);
        Object acr = subject.getClaims().get(CLAIM_ACR);
        if (authTime == null || acr == null) return;
        claim.accept(CLAIM_AUTH_TIME, authTime instanceof Instant i ? i.getEpochSecond() : authTime);
        claim.accept(CLAIM_ACR, acr);
        Object amr = subject.getClaims().get(CLAIM_AMR);
        if (amr != null) claim.accept(CLAIM_AMR, amr);
    }
}
