package com.openwolf.iam.service;

import com.openwolf.iam.auth.TenantClaims;
import com.openwolf.iam.dto.RecoverySessionRequest;
import com.openwolf.iam.dto.RecoverySessionResponse;
import com.openwolf.iam.entity.Principal;
import com.openwolf.iam.entity.RecoveryOperator;
import com.openwolf.iam.exception.ResourceConflictException;
import com.openwolf.iam.repository.PrincipalRepository;
import com.openwolf.iam.repository.RecoveryOperatorRepository;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Clock;
import java.time.Instant;
import java.util.List;
import java.util.UUID;

@Service
@Transactional
public class RecoverySessionService {
    static final String RECOVERY_SCOPE = "identity-admin";
    private static final long MAX_TTL_SECONDS = 900;
    private final RecoveryOperatorRepository operators;
    private final PrincipalRepository principals;
    private final PasswordEncoder passwords;
    private final IamSessionService sessions;
    private final JwtEncoder encoder;
    private final RecoveryAuditService recoveryAudit;
    private final AuditService audit;
    private final Clock clock;
    private final String issuer;
    private final long ttlSeconds;

    @Autowired
    public RecoverySessionService(RecoveryOperatorRepository operators, PrincipalRepository principals,
                                  PasswordEncoder passwords, IamSessionService sessions, JwtEncoder encoder,
                                  RecoveryAuditService recoveryAudit, AuditService audit,
                                  @Value("${spring.security.oauth2.authorizationserver.issuer:http://localhost:8084}") String issuer,
                                  @Value("${iam.identity-recovery.session-ttl-seconds:600}") long ttlSeconds) {
        this(operators, principals, passwords, sessions, encoder, recoveryAudit, audit, issuer, ttlSeconds, Clock.systemUTC());
    }

    RecoverySessionService(RecoveryOperatorRepository operators, PrincipalRepository principals, PasswordEncoder passwords,
                           IamSessionService sessions, JwtEncoder encoder, RecoveryAuditService recoveryAudit,
                           AuditService audit, String issuer, long ttlSeconds, Clock clock) {
        if (ttlSeconds < 1 || ttlSeconds > MAX_TTL_SECONDS) throw new IllegalArgumentException("recovery session TTL must be 1-900 seconds");
        this.operators = operators; this.principals = principals; this.passwords = passwords; this.sessions = sessions;
        this.encoder = encoder; this.recoveryAudit = recoveryAudit; this.audit = audit;
        this.issuer = issuer; this.ttlSeconds = ttlSeconds; this.clock = clock;
    }

    public RecoverySessionResponse issue(RecoverySessionRequest request, HttpServletRequest httpRequest) {
        String tenantId = request.tenantId();
        try { TenantClaims.requireTenant(tenantId); } catch (RuntimeException ex) { return reject(tenantId, "invalid tenant"); }
        if (request.firstOperatorPrincipalId().equals(request.secondOperatorPrincipalId())) return reject(tenantId, "operators must be distinct");

        RecoveryOperator first = operators.findByTenantIdAndPrincipalIdForUpdate(tenantId, request.firstOperatorPrincipalId()).orElse(null);
        RecoveryOperator second = operators.findByTenantIdAndPrincipalIdForUpdate(tenantId, request.secondOperatorPrincipalId()).orElse(null);
        if (!valid(first, request.firstCredential(), tenantId) || !valid(second, request.secondCredential(), tenantId)) {
            return reject(tenantId, "recovery authentication failed");
        }

        Instant now = clock.instant();
        Instant expiresAt = now.plusSeconds(ttlSeconds);
        UUID sessionId = sessions.issueRecovery(tenantId, "recovery:" + UUID.randomUUID(), expiresAt,
                first.getId(), second.getId());
        JwtClaimsSet claims = JwtClaimsSet.builder().issuer(issuer).subject("recovery:" + sessionId)
                .issuedAt(now).expiresAt(expiresAt).audience(List.of("axiom-api"))
                .claim("tenant_id", tenantId).claim("sid", sessionId.toString())
                .claim("recovery", true).claim("recovery_scope", RECOVERY_SCOPE)
                .claim("roles", List.of("platform_admin")).claim("scope", RECOVERY_SCOPE).build();
        String token = encoder.encode(JwtEncoderParameters.from(
                JwsHeader.with(SignatureAlgorithm.RS256).type("at+jwt").build(), claims)).getTokenValue();
        recoveryAuditIssued(tenantId, sessionId, httpRequest);
        return new RecoverySessionResponse(token, "Bearer", ttlSeconds, sessionId, RECOVERY_SCOPE);
    }

    private boolean valid(RecoveryOperator operator, String credential, String tenantId) {
        if (operator == null || operator.getStatus() != RecoveryOperator.Status.ACTIVE
                || operator.getCredentialHash() == null) return false;
        Principal principal = principals.findByIdAndTenantId(operator.getPrincipalId(), tenantId).orElse(null);
        if (principal == null || !principal.isActive()) return false;
        try { return passwords.matches(credential, operator.getCredentialHash()); }
        catch (RuntimeException ex) { return false; }
    }

    private RecoverySessionResponse reject(String tenantId, String reason) {
        recoveryAudit.rejected(tenantId, reason);
        throw new ResourceConflictException("identity recovery authentication failed");
    }

    private void recoveryAuditIssued(String tenantId, UUID sessionId, HttpServletRequest request) {
        // The audit contains only the durable session reference and scope; never the bearer token.
        audit.logRequired(tenantId, audit.currentActor(), "ISSUE_IDENTITY_RECOVERY_SESSION", "session",
                sessionId.toString(), null, java.util.Map.of("recovery", true, "scope", RECOVERY_SCOPE),
                request == null ? null : request.getHeader("X-Correlation-ID"));
    }
}
