package com.openwolf.iam.auth;

import com.openwolf.iam.service.IamSessionService;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;

import java.time.Clock;
import java.time.Instant;
import java.util.UUID;

/** Fail-closed resource-token boundary for durable session revocation. */
public final class SessionTokenValidator implements OAuth2TokenValidator<Jwt> {
    private static final OAuth2Error INVALID = new OAuth2Error("invalid_token");
    private final IamSessionService sessions;
    private final Clock clock;

    public SessionTokenValidator(IamSessionService sessions) { this(sessions, Clock.systemUTC()); }
    SessionTokenValidator(IamSessionService sessions, Clock clock) { this.sessions = sessions; this.clock = clock; }

    @Override
    public OAuth2TokenValidatorResult validate(Jwt token) {
        Object rawId = token.getClaims().get("sid");
        String tenant = token.getClaimAsString("tenant_id");
        boolean recoveryMarked = Boolean.TRUE.equals(token.getClaims().get("recovery"));
        String recoveryScope = token.getClaimAsString("recovery_scope");
        if (!(rawId instanceof String sid) || tenant == null || tenant.isBlank()) return OAuth2TokenValidatorResult.failure(INVALID);
        try {
            UUID id = UUID.fromString(sid);
            boolean active = recoveryMarked
                    ? sessions.active(id, tenant, Instant.now(clock), true, recoveryScope)
                    : sessions.active(id, tenant, Instant.now(clock));
            if (!active) return OAuth2TokenValidatorResult.failure(INVALID);
            sessions.touch(id, tenant, Instant.now(clock));
            return OAuth2TokenValidatorResult.success();
        } catch (RuntimeException ex) {
            return OAuth2TokenValidatorResult.failure(INVALID);
        }
    }
}
