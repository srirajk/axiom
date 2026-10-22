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
                .claim("use_case_id", "caller-supplied-wealth")
                .claim("run_id", "caller-supplied-run")
                .claim("context_id", "caller-supplied-context")
                .claim("branch_id", "caller-supplied-branch")
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
                .doesNotContainKeys("delegation_id", "use_case_id", "run_id", "context_id", "branch_id");
        @SuppressWarnings("unchecked")
        Map<String, Object> actor = (Map<String, Object>) claims.get("act");
        assertThat(actor)
                .containsEntry("sub", "agent:card-assistance:development")
                .containsEntry("client_id", "card-assistance-agent")
                .containsEntry("workload_id", workloadId.toString());
    }

    @Test
    @SuppressWarnings("unchecked")
    void anActorChangeNestsThePriorActorAndTheSameActorDoesNot() {
        OidcClaimEnricher enricher = mock(OidcClaimEnricher.class);
        TenantApplicationService applications = mock(TenantApplicationService.class);
        ApplicationAccessService applicationAccess = mock(ApplicationAccessService.class);
        JwtClaimsCustomizer customizer = new JwtClaimsCustomizer(enricher, applications, applicationAccess);
        for (String client : List.of("agent-b", "argus-gateway-broker")) {
            when(applications.activeAuthority(client)).thenReturn(Optional.of(new TenantApplicationService.ClientAuthority(
                    "meridian", "x", TenantApplicationClient.Type.CONFIDENTIAL_SERVICE, List.of("cards:incident.read"),
                    UUID.randomUUID())));
        }
        String workloadA = UUID.randomUUID().toString();
        Map<String, Object> priorActor = new java.util.LinkedHashMap<>(Map.of(
                "sub", "agent:a", "client_id", "agent-a", "workload_id", workloadA));
        Jwt subject = Jwt.withTokenValue("subject-token").header("alg", "RS256").subject("person-1")
                .issuedAt(Instant.parse("2026-09-21T12:00:00Z")).expiresAt(Instant.parse("2026-09-21T12:05:00Z"))
                .audience(List.of("agent-b-api")).claim("tenant_id", "meridian").claim("identity_kind", "workforce")
                .claim("sid", "root-session").claim("act", priorActor).build();

        // Actor change: workload B continues the chain that workload A started.
        String workloadB = UUID.randomUUID().toString();
        Map<String, Object> changed = issue(customizer, subject, workloadB, "agent:b", "agent-b", "agent-b");
        Map<String, Object> act = (Map<String, Object>) changed.get("act");
        assertThat(changed).containsEntry("sub", "person-1");
        assertThat(act).containsEntry("sub", "agent:b").containsEntry("client_id", "agent-b").containsEntry("workload_id", workloadB);
        assertThat(act.get("act")).as("prior actor nested verbatim").isEqualTo(priorActor);

        // Broker hop: the broker authenticates, the actor stays workload A, and the broker never appears in act.
        Map<String, Object> brokered = issue(customizer, subject, workloadA, "agent:a", "agent-a", "argus-gateway-broker");
        Map<String, Object> same = (Map<String, Object>) brokered.get("act");
        assertThat(brokered).containsEntry("client_id", "argus-gateway-broker");
        assertThat(same).isEqualTo(priorActor).doesNotContainKey("act");
        assertThat(same.toString()).doesNotContain("argus-gateway-broker");
    }

    @Test
    @SuppressWarnings("unchecked")
    void aServiceActingForItselfGetsNoActorAndATakeoverNamesOnlyTheNewActor() {
        OidcClaimEnricher enricher = mock(OidcClaimEnricher.class);
        TenantApplicationService applications = mock(TenantApplicationService.class);
        JwtClaimsCustomizer customizer = new JwtClaimsCustomizer(enricher, applications, mock(ApplicationAccessService.class));
        for (String client : List.of("agent-a", "agent-b", "argus-gateway-broker")) {
            when(applications.activeAuthority(client)).thenReturn(Optional.of(new TenantApplicationService.ClientAuthority(
                    "meridian", "x", TenantApplicationClient.Type.CONFIDENTIAL_SERVICE, List.of("cards:incident.read"),
                    UUID.randomUUID())));
        }
        Jwt own = Jwt.withTokenValue("subject-token").header("alg", "RS256").subject("agent-a")
                .issuedAt(Instant.parse("2026-09-21T12:00:00Z")).expiresAt(Instant.parse("2026-09-21T12:05:00Z"))
                .audience(List.of("agent-a-api")).claim("tenant_id", "meridian").claim("identity_kind", "workload")
                .claim("client_id", "agent-a").build();
        String workloadA = UUID.randomUUID().toString();
        Map<String, Object> self = issue(customizer, own, workloadA, "agent:a", "agent-a", "agent-a");
        assertThat(self).containsEntry("sub", "agent-a").doesNotContainKey("act");
        Map<String, Object> brokered = issue(customizer, own, workloadA, "agent:a", "agent-a",
                "argus-gateway-broker");
        assertThat(brokered).containsEntry("client_id", "argus-gateway-broker").doesNotContainKey("act");
        String workloadB = UUID.randomUUID().toString();
        Map<String, Object> takeover = issue(customizer, own, workloadB, "agent:b", "agent-b", "agent-b");
        assertThat(takeover).containsEntry("sub", "agent-a");
        assertThat((Map<String, Object>) takeover.get("act")).isEqualTo(Map.of("sub", "agent:b", "client_id", "agent-b",
                "workload_id", workloadB));
    }

    @Test
    @SuppressWarnings("unchecked")
    void brokerTargetEmissionKeepsPersonChainAndOmitsSelfActor() {
        TenantApplicationService applications = mock(TenantApplicationService.class);
        when(applications.activeAuthority("argus-gateway-broker")).thenReturn(Optional.of(
                new TenantApplicationService.ClientAuthority("meridian", "argus-gateway",
                        TenantApplicationClient.Type.CONFIDENTIAL_SERVICE,
                        List.of("cards:incident.read"), UUID.randomUUID())));
        JwtClaimsCustomizer customizer = new JwtClaimsCustomizer(mock(OidcClaimEnricher.class), applications,
                mock(ApplicationAccessService.class));
        String actorId = UUID.randomUUID().toString();
        Map<String, Object> prior = Map.of("sub", "agent:prior", "client_id", "prior-client",
                "workload_id", UUID.randomUUID().toString());
        Map<String, Object> current = Map.of("sub", "agent:source", "client_id", "source-client",
                "workload_id", actorId, "act", prior);
        Jwt person = Jwt.withTokenValue("person-gateway").header("alg", "RS256").subject("person-1")
                .issuedAt(Instant.parse("2026-09-21T12:00:00Z"))
                .expiresAt(Instant.parse("2026-09-21T12:05:00Z"))
                .audience(List.of("argus-gateway")).claim("tenant_id", "meridian")
                .claim("identity_kind", "workforce").claim("act", current)
                .claim("authority_id", UUID.randomUUID().toString()).build();
        Map<String, Object> personResult = issueBrokerTarget(customizer, person, actorId,
                "agent:source", "source-client");
        assertThat(personResult).containsEntry("sub", "person-1")
                .containsEntry("client_id", "argus-gateway-broker")
                .containsEntry("authority_profile", "gateway_backend");
        assertThat(personResult.get("authority_id").toString()).startsWith("broker-target:");
        assertThat(personResult).containsEntry("source_gateway_route_id", person.getClaimAsString("authority_id"));
        assertThat((Map<String, Object>) personResult.get("act")).isEqualTo(current);

        Jwt self = Jwt.withTokenValue("self-gateway").header("alg", "RS256").subject("source-client")
                .issuedAt(Instant.parse("2026-09-21T12:00:00Z"))
                .expiresAt(Instant.parse("2026-09-21T12:05:00Z"))
                .audience(List.of("argus-gateway")).claim("tenant_id", "meridian")
                .claim("identity_kind", "workload").claim("client_id", "source-client")
                .claim("authority_id", UUID.randomUUID().toString()).build();
        Map<String, Object> selfResult = issueBrokerTarget(customizer, self, actorId,
                "agent:source", "source-client");
        assertThat(selfResult).containsEntry("sub", "source-client")
                .containsEntry("source_workload_id", actorId)
                .containsEntry("source_gateway_route_id", self.getClaimAsString("authority_id"))
                .doesNotContainKey("act");
    }

    private Map<String, Object> issueBrokerTarget(JwtClaimsCustomizer customizer, Jwt subject,
                                                   String workloadId, String workloadRef, String actorClientId) {
        TokenExchangeAuthenticationToken exchange = new TokenExchangeAuthenticationToken(mock(Authentication.class),
                subject.getTokenValue(), "next-api", Set.of("cards:incident.read"), Map.of());
        exchange.bindAuthority(new TokenExchangeAuthenticationToken.AuthorityContext(subject, "next-api", "purpose",
                "gateway_backend", "broker-target:" + UUID.randomUUID(), null, "exchange_subject",
                subject.getClaimAsString("identity_kind"), workloadId, workloadRef, actorClientId));
        JwtEncodingContext context = context(exchange, "argus-gateway-broker");
        customizer.jwtTokenCustomizer().customize(context);
        return context.getClaims().build().getClaims();
    }

    private Map<String, Object> issue(JwtClaimsCustomizer customizer, Jwt subject, String workloadId, String workloadRef,
                                      String actorClientId, String requester) {
        TokenExchangeAuthenticationToken exchange = new TokenExchangeAuthenticationToken(mock(Authentication.class),
                "subject-token", "next-api", Set.of("cards:incident.read"), Map.of());
        exchange.bindAuthority(new TokenExchangeAuthenticationToken.AuthorityContext(subject, "next-api", "purpose",
                "workload_continuation", UUID.randomUUID().toString(), null, "gateway_authorization", "workforce",
                workloadId, workloadRef, actorClientId));
        JwtEncodingContext context = context(exchange, requester);
        JwtClaimsSet.Builder builder = context.getClaims();
        customizer.jwtTokenCustomizer().customize(context);
        return builder.build().getClaims();
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
