package com.openwolf.iam.auth;

import com.openwolf.iam.entity.TenantApplicationClient;
import com.openwolf.iam.service.ApplicationAccessService;
import com.openwolf.iam.service.TenantApplicationService;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class JwtClaimsCustomizerTokenExchangeTest {
    @Test
    void gatewayExchangePreservesSubjectAndCarriesOneStructuredBusinessActor() {
        OidcClaimEnricher enricher = mock(OidcClaimEnricher.class);
        TenantApplicationService applications = mock(TenantApplicationService.class);
        ApplicationAccessService applicationAccess = mock(ApplicationAccessService.class);
        JwtClaimsCustomizer customizer = new JwtClaimsCustomizer(enricher, applications, applicationAccess);
        when(applications.activeAuthority("argus-gateway-broker")).thenReturn(Optional.of(
                new TenantApplicationService.ClientAuthority("meridian", "argus-gateway",
                        TenantApplicationClient.Type.CONFIDENTIAL_SERVICE,
                        List.of("cards:incident.read"), UUID.randomUUID())));

        Jwt subject = Jwt.withTokenValue("subject-token")
                .header("alg", "RS256")
                .subject("meridian-1008")
                .issuedAt(Instant.parse("2026-09-21T12:00:00Z"))
                .expiresAt(Instant.parse("2026-09-21T12:05:00Z"))
                .audience(List.of("argus-gateway"))
                .claim("tenant_id", "meridian")
                .claim("identity_kind", "workforce")
                .claim("sid", "root-session")
                .build();
        Authentication clientPrincipal = mock(Authentication.class);
        TokenExchangeAuthenticationToken exchange = new TokenExchangeAuthenticationToken(
                clientPrincipal, "subject-token", "card-actions-api",
                Set.of("cards:incident.read"), Map.of());
        UUID workloadId = UUID.randomUUID();
        UUID routeId = UUID.randomUUID();
        exchange.bindAuthority(new TokenExchangeAuthenticationToken.AuthorityContext(
                subject, "card-actions-api", "Delegate bounded card action work",
                "gateway_backend", routeId.toString(), null, "exchange_subject", "workforce",
                workloadId.toString(), "agent:card-assistance:development", "card-assistance-agent"));

        JwtEncodingContext context = context(exchange, "argus-gateway-broker");
        JwtClaimsSet.Builder claimBuilder = context.getClaims();
        customizer.jwtTokenCustomizer().customize(context);

        Map<String, Object> claims = claimBuilder.build().getClaims();
        assertThat(claims)
                .containsEntry("sub", "meridian-1008")
                .containsEntry("aud", List.of("card-actions-api"))
                .containsEntry("client_id", "argus-gateway-broker")
                .containsEntry("azp", "argus-gateway-broker")
                .containsEntry("identity_kind", "workforce")
                .containsEntry("authority_profile", "gateway_backend")
                .containsEntry("authority_id", routeId.toString())
                .containsEntry("token_use", "exchange_subject")
                .containsEntry("subject_sid", "root-session")
                .doesNotContainKey("delegation_id");
        @SuppressWarnings("unchecked")
        Map<String, Object> actor = (Map<String, Object>) claims.get("act");
        assertThat(actor)
                .containsEntry("sub", "agent:card-assistance:development")
                .containsEntry("client_id", "card-assistance-agent")
                .containsEntry("workload_id", workloadId.toString());
    }

    @Test
    void directCustomerProfileRetainsItsImmutableDelegationPin() {
        OidcClaimEnricher enricher = mock(OidcClaimEnricher.class);
        TenantApplicationService applications = mock(TenantApplicationService.class);
        JwtClaimsCustomizer customizer = new JwtClaimsCustomizer(
                enricher, applications, mock(ApplicationAccessService.class));
        when(applications.activeAuthority("card-assistance-agent")).thenReturn(Optional.of(
                new TenantApplicationService.ClientAuthority("meridian", "cards-api",
                        TenantApplicationClient.Type.CONFIDENTIAL_SERVICE,
                        List.of("cards:incident.read"), UUID.randomUUID())));
        UUID customerId = UUID.randomUUID();
        UUID workloadId = UUID.randomUUID();
        UUID delegationId = UUID.randomUUID();
        Jwt subject = Jwt.withTokenValue("customer-token")
                .header("alg", "RS256")
                .subject(customerId.toString())
                .issuedAt(Instant.parse("2026-09-21T12:00:00Z"))
                .expiresAt(Instant.parse("2026-09-21T12:05:00Z"))
                .audience(List.of(TokenExchangeConstants.SUBJECT_AUDIENCE))
                .claim("tenant_id", "meridian")
                .claim("identity_kind", "customer")
                .build();
        TokenExchangeAuthenticationToken exchange = new TokenExchangeAuthenticationToken(
                mock(Authentication.class), "customer-token", "cards-api",
                Set.of("cards:incident.read"), Map.of());
        exchange.bindAuthority(new TokenExchangeAuthenticationToken.AuthorityContext(
                subject, "cards-api", "Report a lost card", "ciam_customer",
                delegationId.toString(), delegationId.toString(), "delegated_access", "customer",
                workloadId.toString(), "agent:card-assistance:development", "card-assistance-agent"));

        JwtEncodingContext context = context(exchange, "card-assistance-agent");
        JwtClaimsSet.Builder claimBuilder = context.getClaims();
        customizer.jwtTokenCustomizer().customize(context);

        assertThat(claimBuilder.build().getClaims())
                .containsEntry("sub", customerId.toString())
                .containsEntry("delegation_id", delegationId.toString())
                .containsEntry("authority_profile", "ciam_customer")
                .containsEntry("token_use", "delegated_access");
    }

    private static JwtEncodingContext context(TokenExchangeAuthenticationToken exchange, String clientId) {
        JwtEncodingContext context = mock(JwtEncodingContext.class);
        RegisteredClient client = mock(RegisteredClient.class);
        Authentication principal = mock(Authentication.class);
        when(context.getRegisteredClient()).thenReturn(client);
        when(client.getClientId()).thenReturn(clientId);
        when(context.getPrincipal()).thenReturn(principal);
        when(principal.getName()).thenReturn(clientId);
        when(context.getTokenType()).thenReturn(OAuth2TokenType.ACCESS_TOKEN);
        when(context.getAuthorizationGrantType()).thenReturn(TokenExchangeConstants.GRANT_TYPE);
        when(context.getAuthorizationGrant()).thenReturn(exchange);
        when(context.getJwsHeader()).thenReturn(JwsHeader.with(() -> "RS256"));
        JwtClaimsSet.Builder claims = JwtClaimsSet.builder();
        when(context.getClaims()).thenReturn(claims);
        return context;
    }
}
