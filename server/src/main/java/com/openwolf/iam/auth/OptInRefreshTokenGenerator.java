package com.openwolf.iam.auth;

import java.time.Clock;
import java.time.Instant;
import java.util.Base64;
import org.springframework.security.crypto.keygen.Base64StringKeyGenerator;
import org.springframework.security.oauth2.core.*;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.token.*;

/** Public refresh families retain their first expiry across rotations; confidential-client policy is unchanged. */
public final class OptInRefreshTokenGenerator implements OAuth2TokenGenerator<OAuth2RefreshToken> {
    public static final String ABSOLUTE_LIFETIME = "settings.client.axiom.absolute-refresh-lifetime";
    private final OAuth2RefreshTokenGenerator standard = new OAuth2RefreshTokenGenerator();
    private final Base64StringKeyGenerator random = new Base64StringKeyGenerator(Base64.getUrlEncoder().withoutPadding(), 96);
    private final Clock clock;
    public OptInRefreshTokenGenerator() { this(Clock.systemUTC()); }
    OptInRefreshTokenGenerator(Clock clock) { this.clock = clock; }
    @Override public OAuth2RefreshToken generate(OAuth2TokenContext context) {
        if (!OAuth2TokenType.REFRESH_TOKEN.equals(context.getTokenType()) || !OfflineAccess.granted(context)
                || !context.getRegisteredClient().getAuthorizationGrantTypes().contains(AuthorizationGrantType.REFRESH_TOKEN)) return null;
        if (!Boolean.TRUE.equals(context.getRegisteredClient().getClientSettings().getSetting(ABSOLUTE_LIFETIME))) {
            return standard.generate(context);
        }
        var methods = context.getRegisteredClient().getClientAuthenticationMethods();
        boolean publicClient = methods.equals(java.util.Set.of(ClientAuthenticationMethod.NONE));
        boolean keyCimd = methods.equals(java.util.Set.of(ClientAuthenticationMethod.PRIVATE_KEY_JWT))
                && context.getRegisteredClient().getClientSettings().getSetting(CimdRegisteredClientRepository.CLIENT_ID) != null;
        if (!(publicClient || keyCimd) || context.getRegisteredClient().getTokenSettings().isReuseRefreshTokens()) return null;
        Instant now = clock.instant();
        var existing = context.getAuthorization() == null ? null : context.getAuthorization().getRefreshToken();
        Instant expiry = existing == null ? now.plus(context.getRegisteredClient().getTokenSettings().getRefreshTokenTimeToLive())
                : existing.getToken().getExpiresAt();
        if (expiry == null || !expiry.isAfter(now)) throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_GRANT);
        return new OAuth2RefreshToken(random.generateKey(), now, expiry);
    }
}
