package com.openwolf.iam.auth;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.script.DefaultRedisScript;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.util.HexFormat;
import java.util.List;
import java.util.UUID;

/**
 * Serializes redemption attempts for one authorization code across Axiom instances.
 *
 * <p>Spring Authorization Server persists the consumed marker on the authorization itself, but its
 * service contract performs {@code findByToken} and {@code save} as separate calls. Without a
 * cross-instance lock, two concurrent requests can both observe an unconsumed code. This short,
 * owner-qualified Redis lock spans validation and persistence. Invalid attempts release it without
 * consuming the code; after the first valid request completes, the framework's persisted consumed
 * marker makes every replay fail closed.</p>
 *
 * <p>Refresh-token redemption is serialized the same way, but without waiting: a second request presenting the same
 * refresh token while the first is in flight is refused at once ({@code invalid_grant}); one presenting it after the
 * first completed is a reuse of a spent token, which withdraws the whole refresh family
 * ({@link RedisOAuth2AuthorizationService}). Exactly one of several concurrent redemptions can succeed.</p>
 */
@Component
public final class AuthorizationCodeRedemptionLockFilter extends OncePerRequestFilter {
    static final String TOKEN_ENDPOINT = "/oauth/token";
    private static final Duration LOCK_TTL = Duration.ofSeconds(30);
    private static final long DEFAULT_WAIT_MILLIS = 2_000;
    private static final DefaultRedisScript<Long> RELEASE = new DefaultRedisScript<>(
            "if redis.call('get', KEYS[1]) == ARGV[1] then "
                    + "return redis.call('del', KEYS[1]) else return 0 end",
            Long.class);

    private final StringRedisTemplate redis;
    private final String keyPrefix;
    private final long waitMillis;

    @Autowired
    public AuthorizationCodeRedemptionLockFilter(
            StringRedisTemplate redis,
            @Value("${iam.oauth2.authorization-store.redis.key-prefix:iam:oauth2}") String keyPrefix) {
        this(redis, keyPrefix, DEFAULT_WAIT_MILLIS);
    }

    AuthorizationCodeRedemptionLockFilter(
            StringRedisTemplate redis,
            String keyPrefix,
            long waitMillis) {
        this.redis = redis;
        this.keyPrefix = keyPrefix;
        this.waitMillis = waitMillis;
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        String grant = request.getParameter("grant_type");
        return !TOKEN_ENDPOINT.equals(request.getRequestURI())
                || !"POST".equalsIgnoreCase(request.getMethod())
                || !("authorization_code".equals(grant) || "refresh_token".equals(grant));
    }

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain) throws ServletException, IOException {
        boolean refresh = "refresh_token".equals(request.getParameter("grant_type"));
        String code = request.getParameter(refresh ? "refresh_token" : "code");
        if (code == null || code.isBlank()) {
            filterChain.doFilter(request, response);
            return;
        }

        String key = keyPrefix + (refresh ? ":refresh-redemption-lock:" : ":code-redemption-lock:") + sha256(code);
        String owner = UUID.randomUUID().toString();
        if (!acquire(key, owner, refresh ? 0 : waitMillis)) {
            invalidGrant(response);
            return;
        }
        try {
            filterChain.doFilter(request, response);
        } finally {
            redis.execute(RELEASE, List.of(key), owner);
        }
    }

    private boolean acquire(String key, String owner, long waitFor) {
        long deadline = System.nanoTime() + Duration.ofMillis(waitFor).toNanos();
        do {
            if (Boolean.TRUE.equals(redis.opsForValue().setIfAbsent(key, owner, LOCK_TTL))) {
                return true;
            }
            try {
                Thread.sleep(10);
            } catch (InterruptedException interrupted) {
                Thread.currentThread().interrupt();
                return false;
            }
        } while (System.nanoTime() < deadline);
        return false;
    }

    private static void invalidGrant(HttpServletResponse response) throws IOException {
        response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setHeader("Cache-Control", "no-store");
        response.getWriter().write("{\"error\":\"invalid_grant\"}");
    }

    private static String sha256(String value) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
                    .digest(value.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException unavailable) {
            throw new IllegalStateException("SHA-256 is not available", unavailable);
        }
    }
}
