package com.openwolf.iam.auth;

import com.openwolf.iam.service.IamSessionService;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;

import java.util.List;

/**
 * Session boundary used only while decoding an RFC 8693 subject token.
 *
 * <p>An original client-credentials workload token has no human session. This validator admits only
 * that narrow token shape to the subsequent {@link TokenExchangeSubjectAuthorityValidator}, which
 * proves the active confidential client, workload binding, tenant, and exact audience. Every customer,
 * workforce, recovery, or already-exchanged token continues through the durable session validator.
 */
public final class TokenExchangeSessionValidator implements OAuth2TokenValidator<Jwt> {
    private final OAuth2TokenValidator<Jwt> sessions;

    public TokenExchangeSessionValidator(IamSessionService sessions) {
        this(new SessionTokenValidator(sessions));
    }

    TokenExchangeSessionValidator(OAuth2TokenValidator<Jwt> sessions) {
        this.sessions = sessions;
    }

    @Override
    public OAuth2TokenValidatorResult validate(Jwt token) {
        return isOriginalSessionlessWorkload(token)
                ? OAuth2TokenValidatorResult.success()
                : sessions.validate(token);
    }

    private static boolean isOriginalSessionlessWorkload(Jwt token) {
        String tenantId = token.getClaimAsString("tenant_id");
        String clientId = token.getClaimAsString("client_id");
        List<String> audience = token.getAudience();
        return !token.getClaims().containsKey("sid")
                && "workload".equals(token.getClaimAsString("identity_kind"))
                && !token.getClaims().containsKey("act")
                && !token.getClaims().containsKey("token_use")
                && !token.getClaims().containsKey("authority_profile")
                && !token.getClaims().containsKey("authority_id")
                && !token.getClaims().containsKey("subject_sid")
                && !token.getClaims().containsKey("recovery")
                && tenantId != null && !tenantId.isBlank()
                && clientId != null && !clientId.isBlank()
                && clientId.equals(token.getSubject())
                && audience != null && audience.size() == 1
                && audience.getFirst() != null && !audience.getFirst().isBlank();
    }
}
