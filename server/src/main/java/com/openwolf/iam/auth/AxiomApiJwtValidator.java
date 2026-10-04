package com.openwolf.iam.auth;

import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;

import java.util.Locale;
import java.util.Set;

/**
 * Axiom resource APIs accept only Admin-targeted RFC 9068 access tokens minted by platform-owned paths.
 *
 * <p>The audience alone is not sufficient: a tenant application could carry the {@code axiom-api} audience (created
 * before audiences were reserved, or otherwise), and its access tokens carry tenant-defined application role keys in
 * {@code roles}. Such tokens must never be accepted here. Accepted tokens are therefore restricted to:
 * <ul>
 *   <li>tokens issued by {@code /auth/login} (no {@code client_id} claim), and</li>
 *   <li>tokens issued to a platform-owned OAuth client ({@link #PLATFORM_CLIENT_IDS}),</li>
 * </ul>
 * and every token carrying tenant-application or token-exchange claims is rejected.
 */
public final class AxiomApiJwtValidator implements OAuth2TokenValidator<Jwt> {
    public static final String AUDIENCE = "axiom-api";
    /** Audiences that tenant applications may not use. Compared case-insensitively. */
    public static final Set<String> RESERVED_AUDIENCES = Set.of(AUDIENCE);
    /** OAuth clients owned by the platform deployment (see SecurityConfig#requiredSystemClients). */
    public static final Set<String> PLATFORM_CLIENT_IDS = Set.of("axiom-admin");
    /** Claims that only tenant-application or exchanged tokens carry. */
    private static final Set<String> APPLICATION_TOKEN_CLAIMS = Set.of(
            "application_id", "act", "token_use", "authority_profile", "authority_id", "delegation_id");
    private static final OAuth2Error INVALID = new OAuth2Error("invalid_token");

    @Override
    public OAuth2TokenValidatorResult validate(Jwt token) {
        if (token.getAudience().size() != 1 || !token.getAudience().contains(AUDIENCE)
                || !"at+jwt".equals(token.getHeaders().get("typ"))) {
            return OAuth2TokenValidatorResult.failure(INVALID);
        }
        if (APPLICATION_TOKEN_CLAIMS.stream().anyMatch(token.getClaims()::containsKey)) {
            return OAuth2TokenValidatorResult.failure(INVALID);
        }
        if (token.getClaims().containsKey("client_id")
                && !PLATFORM_CLIENT_IDS.contains(token.getClaimAsString("client_id"))) {
            return OAuth2TokenValidatorResult.failure(INVALID);
        }
        return OAuth2TokenValidatorResult.success();
    }

    public static boolean isReservedAudience(String audience) {
        return audience != null && RESERVED_AUDIENCES.contains(audience.trim().toLowerCase(Locale.ROOT));
    }
}
