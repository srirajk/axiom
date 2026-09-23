package com.openwolf.iam.service;

import com.openwolf.iam.dto.CiamContracts.CustomerTokenResponse;
import com.openwolf.iam.auth.BusinessScopeRegistry;
import com.openwolf.iam.auth.TokenExchangeConstants;
import com.openwolf.iam.entity.TenantApplicationClient;
import org.springframework.beans.factory.annotation.Value;
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
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.UUID;

@Service
@Transactional
public class CiamCustomerTokenService {
    private final CiamCustomerAuthenticationService authentication;
    private final IamSessionService sessions;
    private final JwtEncoder encoder;
    private final String issuer;
    private final long ttlSeconds;
    private final Clock clock;
    private final TenantApplicationService applications;
    private final BusinessScopeRegistry businessScopes;
    private final CiamLifecycleAuditService audit;

    @org.springframework.beans.factory.annotation.Autowired
    public CiamCustomerTokenService(CiamCustomerAuthenticationService authentication,
                                    IamSessionService sessions, JwtEncoder encoder,
                                    @Value("${spring.security.oauth2.authorizationserver.issuer:http://localhost:8084}")
                                    String issuer,
                                    @Value("${iam.ciam.customer-token-ttl-seconds:300}") long ttlSeconds,
                                    TenantApplicationService applications,
                                    BusinessScopeRegistry businessScopes,
                                    CiamLifecycleAuditService audit) {
        this(authentication, sessions, encoder, issuer, ttlSeconds, Clock.systemUTC(), applications,
                businessScopes, audit);
    }

    CiamCustomerTokenService(CiamCustomerAuthenticationService authentication,
                             IamSessionService sessions, JwtEncoder encoder,
                             String issuer, long ttlSeconds, Clock clock,
                             TenantApplicationService applications, BusinessScopeRegistry businessScopes,
                             CiamLifecycleAuditService audit) {
        if (ttlSeconds < 30 || ttlSeconds > 600) {
            throw new IllegalArgumentException("customer subject token TTL must be between 30 and 600 seconds");
        }
        this.authentication = authentication;
        this.sessions = sessions;
        this.encoder = encoder;
        this.issuer = issuer;
        this.ttlSeconds = ttlSeconds;
        this.clock = clock;
        this.applications = applications;
        this.businessScopes = businessScopes;
        this.audit = audit;
    }

    public CustomerTokenResponse issue(String tenantId, String email, String password,
                                       String clientId, Set<String> requestedScopes, String correlationId) {
        var customer = authentication.authenticate(tenantId, email, password);
        var client = applications.activeAuthority(clientId)
                .filter(authority -> authority.clientType() == TenantApplicationClient.Type.PUBLIC_BROWSER)
                .filter(authority -> authority.tenantId().equals(tenantId))
                .orElseThrow(() -> new IllegalArgumentException("customer client is disabled or unknown"));
        TreeSet<String> scopes = new TreeSet<>(requestedScopes);
        if (scopes.isEmpty() || !client.scopes().containsAll(scopes)
                || scopes.stream().anyMatch(scope -> !businessScopes.isApproved(scope))) {
            throw new IllegalArgumentException("customer token scopes are not approved for this client");
        }
        Instant now = clock.instant();
        Instant expiresAt = now.plusSeconds(ttlSeconds);
        String authorizationId = "ciam:" + UUID.randomUUID();
        UUID sessionId = sessions.issue(authorizationId, tenantId, customer.customerId().toString(),
                client.applicationId(), clientId, expiresAt);
        JwtClaimsSet claims = JwtClaimsSet.builder()
                .issuer(issuer)
                .subject(customer.customerId().toString())
                .issuedAt(now)
                .expiresAt(expiresAt)
                .id(UUID.randomUUID().toString())
                .audience(List.of(TokenExchangeConstants.SUBJECT_AUDIENCE))
                .claim("tenant_id", tenantId)
                .claim("identity_kind", "customer")
                .claim("token_version", customer.tokenVersion())
                .claim("client_id", clientId)
                .claim("sid", sessionId.toString())
                .claim("scope", String.join(" ", scopes))
                .build();
        String token = encoder.encode(JwtEncoderParameters.from(
                JwsHeader.with(SignatureAlgorithm.RS256).type("at+jwt").build(), claims)).getTokenValue();
        audit.record(tenantId, customer.customerId().toString(), "CUSTOMER_SUBJECT_TOKEN_ISSUED",
                "customer_session", sessionId.toString(), Map.of("clientId", clientId,
                        "scopes", scopes, "expiresAt", expiresAt.toString()), correlationId);
        return new CustomerTokenResponse(token, "Bearer", ttlSeconds,
                customer.customerId(), customer.identityKind(), clientId, Set.copyOf(scopes));
    }
}
